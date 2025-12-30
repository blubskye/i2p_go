// Package router implements the I2P router core.
package router

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/garlic"
	"github.com/go-i2p/go-i2p/pkg/i2np"
	"github.com/go-i2p/go-i2p/pkg/netdb"
	"github.com/go-i2p/go-i2p/pkg/transport/ntcp2"
	"github.com/go-i2p/go-i2p/pkg/transport/ssu2"
	"github.com/go-i2p/go-i2p/pkg/tunnel"
)

// Router states
const (
	RouterStateStopped = iota
	RouterStateStarting
	RouterStateRunning
	RouterStateStopping
)

// Router is the main I2P router.
type Router struct {
	mu sync.RWMutex

	config  *Config
	context *Context
	state   int

	// Transport servers
	ntcp2Server *ntcp2.Server
	ssu2Server  *ssu2.Server

	// Core components
	netDb         *netdb.NetDb
	tunnelManager *tunnel.Manager
	garlicHandler *garlic.Handler

	// Message handling
	messageQueue chan *routerMessage

	// Callbacks
	onRouterInfoReceived func(*data.RouterInfo)
	onMessageReceived    func(*i2np.RawMessage)

	done chan struct{}
}

// routerMessage represents a message to process.
type routerMessage struct {
	from    data.Hash
	msg     *i2np.RawMessage
	session interface{}
}

// New creates a new router.
func New(config *Config) (*Router, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create router context
	ctx, err := NewContext(config)
	if err != nil {
		return nil, err
	}

	r := &Router{
		config:       config,
		context:      ctx,
		state:        RouterStateStopped,
		messageQueue: make(chan *routerMessage, 1000),
		done:         make(chan struct{}),
	}

	// Initialize components
	if err := r.initComponents(); err != nil {
		return nil, err
	}

	return r, nil
}

// initComponents initializes all router components.
func (r *Router) initComponents() error {
	identHash := r.context.IdentHash()

	// Initialize NetDb
	r.netDb = netdb.NewNetDb(identHash, r.config.DataDir+"/netDb")
	r.netDb.SetMessageSender(r.sendI2NPMessage)

	// Initialize tunnel manager
	r.tunnelManager = tunnel.NewManager(identHash)
	r.tunnelManager.SetMessageSender(r.sendI2NPMessage)
	r.tunnelManager.SetPeerSelector(r)

	// Initialize garlic handler
	r.garlicHandler = garlic.NewHandler(
		identHash,
		r.context.EncryptionKeys().PrivateKey(),
		uint16(crypto.CryptoKeyECIES_X25519),
	)
	r.garlicHandler.SetDeliveryCallbacks(
		r.onLocalDelivery,
		r.onRouterDelivery,
		r.onTunnelDelivery,
	)

	return nil
}

// Start starts the router.
func (r *Router) Start() error {
	r.mu.Lock()
	if r.state != RouterStateStopped {
		r.mu.Unlock()
		return errors.New("router: already running")
	}
	r.state = RouterStateStarting
	r.mu.Unlock()

	// Start NetDb
	if err := r.netDb.Start(); err != nil {
		r.setState(RouterStateStopped)
		return err
	}

	// Reseed if needed
	reseeder := netdb.NewReseeder(r.netDb)
	if reseeder.NeedsReseed() {
		_, _ = reseeder.Reseed()
	}

	// Start transports
	if err := r.startTransports(); err != nil {
		r.netDb.Stop()
		r.setState(RouterStateStopped)
		return err
	}

	// Build and publish RouterInfo
	r.publishRouterInfo()

	// Start tunnel manager
	if err := r.tunnelManager.Start(); err != nil {
		r.stopTransports()
		r.netDb.Stop()
		r.setState(RouterStateStopped)
		return err
	}

	// Start garlic handler
	r.garlicHandler.Start()

	// Start message processing
	go r.messageLoop()
	go r.maintenanceLoop()

	r.setState(RouterStateRunning)
	return nil
}

// Stop stops the router.
func (r *Router) Stop() {
	r.mu.Lock()
	if r.state != RouterStateRunning {
		r.mu.Unlock()
		return
	}
	r.state = RouterStateStopping
	r.mu.Unlock()

	close(r.done)

	r.garlicHandler.Stop()
	r.tunnelManager.Stop()
	r.stopTransports()
	r.netDb.Stop()

	r.setState(RouterStateStopped)
}

// startTransports starts NTCP2 and SSU2 servers.
func (r *Router) startTransports() error {
	// Start NTCP2
	if r.config.NTCP2Addr != "" {
		r.ntcp2Server = ntcp2.NewServer(&ntcp2.ServerConfig{
			ListenAddr:     r.config.NTCP2Addr,
			LocalIdentity:  r.context.Identity().ToBuffer(),
			LocalStaticKey: r.context.NTCP2Keys(),
			OnSession:      r.onNTCP2Session,
			OnMessage:      r.onNTCP2Message,
		})

		if err := r.ntcp2Server.Start(); err != nil {
			return err
		}
	}

	// Start SSU2
	if r.config.SSU2Addr != "" {
		r.ssu2Server = ssu2.NewServer(&ssu2.ServerConfig{
			ListenAddr:     r.config.SSU2Addr,
			LocalIdentity:  r.context.Identity().ToBuffer(),
			LocalStaticKey: r.context.NTCP2Keys(),
			OnSession:      r.onSSU2Session,
			OnMessage:      r.onSSU2Message,
		})

		if err := r.ssu2Server.Start(); err != nil {
			if r.ntcp2Server != nil {
				r.ntcp2Server.Stop()
			}
			return err
		}
	}

	return nil
}

// stopTransports stops all transport servers.
func (r *Router) stopTransports() {
	if r.ntcp2Server != nil {
		r.ntcp2Server.Stop()
	}
	if r.ssu2Server != nil {
		r.ssu2Server.Stop()
	}
}

// publishRouterInfo builds and publishes our RouterInfo.
func (r *Router) publishRouterInfo() {
	caps := data.CapsReachable // Reachable
	if r.config.Floodfill {
		caps |= data.CapsFloodfill // Floodfill
	}

	ri := r.context.BuildRouterInfo(r.config.NTCP2Addr, r.config.SSU2Addr, caps)
	r.netDb.PublishRouterInfo(ri)
}

// sendI2NPMessage sends an I2NP message to a destination.
func (r *Router) sendI2NPMessage(dest data.Hash, msg *i2np.RawMessage) error {
	// Try to find an existing session
	// First try NTCP2
	if r.ntcp2Server != nil {
		sessions := r.ntcp2Server.Sessions()
		for _, session := range sessions {
			if session.RemoteIdentHash() == dest {
				return session.SendMessage(msg)
			}
		}
	}

	// Try SSU2
	if r.ssu2Server != nil {
		sessions := r.ssu2Server.Sessions()
		for _, session := range sessions {
			// Would need to get the remote identity hash
			_ = session
		}
	}

	// No existing session - need to establish one
	ri, err := r.netDb.GetRouterInfo(dest)
	if err != nil {
		return err
	}

	// Try to connect
	return r.connectAndSend(ri, msg)
}

// connectAndSend establishes a connection and sends a message.
func (r *Router) connectAndSend(ri *data.RouterInfo, msg *i2np.RawMessage) error {
	identHash := ri.GetIdentHash()

	// Try NTCP2 first
	ntcp2Addr := ri.GetNTCP2Address(true)
	if ntcp2Addr != nil && r.ntcp2Server != nil && ntcp2Addr.Host != nil {
		addr := fmt.Sprintf("%s:%d", ntcp2Addr.Host.String(), ntcp2Addr.Port)
		session, err := r.ntcp2Server.Connect(addr, ntcp2Addr.StaticKey[:], identHash)
		if err == nil {
			return session.SendMessage(msg)
		}
	}

	// Try SSU2
	ssu2Addr := ri.GetSSU2Address(true)
	if ssu2Addr != nil && r.ssu2Server != nil && ssu2Addr.Host != nil {
		addr := fmt.Sprintf("%s:%d", ssu2Addr.Host.String(), ssu2Addr.Port)
		session, err := r.ssu2Server.Connect(addr, ssu2Addr.StaticKey[:], identHash)
		if err == nil {
			return session.SendMessage(msg)
		}
	}

	return errors.New("router: unable to connect to peer")
}

// onNTCP2Session handles a new NTCP2 session.
func (r *Router) onNTCP2Session(session *ntcp2.Session) {
	// Session established
}

// onNTCP2Message handles an NTCP2 message.
func (r *Router) onNTCP2Message(session *ntcp2.Session, msg *i2np.RawMessage) {
	r.messageQueue <- &routerMessage{
		from:    session.RemoteIdentHash(),
		msg:     msg,
		session: session,
	}
}

// onSSU2Session handles a new SSU2 session.
func (r *Router) onSSU2Session(session *ssu2.Session) {
	// Session established
}

// onSSU2Message handles an SSU2 message.
func (r *Router) onSSU2Message(session *ssu2.Session, msg *i2np.RawMessage) {
	r.messageQueue <- &routerMessage{
		msg:     msg,
		session: session,
	}
}

// messageLoop processes incoming messages.
func (r *Router) messageLoop() {
	for {
		select {
		case <-r.done:
			return
		case rm := <-r.messageQueue:
			r.processMessage(rm)
		}
	}
}

// processMessage processes a single message.
func (r *Router) processMessage(rm *routerMessage) {
	msg := rm.msg

	switch msg.Type() {
	case i2np.TypeDatabaseStore:
		ds, err := i2np.ParseDatabaseStore(msg.Payload())
		if err == nil {
			r.netDb.HandleDatabaseStore(ds)
		}

	case i2np.TypeDatabaseLookup:
		dl, err := i2np.ParseDatabaseLookup(msg.Payload())
		if err == nil {
			reply, _ := r.netDb.HandleDatabaseLookup(dl)
			if reply != nil {
				// Send reply back
				r.sendI2NPMessage(rm.from, reply.ToRawMessage())
			}
		}

	case i2np.TypeDatabaseSearchReply:
		dsr, err := i2np.ParseDatabaseSearchReply(msg.Payload())
		if err == nil {
			r.netDb.HandleDatabaseSearchReply(dsr)
		}

	case i2np.TypeTunnelData:
		td, err := i2np.ParseTunnelData(msg.Payload())
		if err == nil {
			r.tunnelManager.HandleTunnelData(tunnel.TunnelID(td.TunnelID), td.Data[:])
		}

	case i2np.TypeVariableTunnelBuild:
		vtb, err := i2np.ParseVariableTunnelBuild(msg.Payload())
		if err == nil {
			r.tunnelManager.HandleTunnelBuild(vtb)
		}

	case i2np.TypeVariableTunnelBuildReply:
		vtbr, err := i2np.ParseVariableTunnelBuildReply(msg.Payload())
		if err == nil {
			r.tunnelManager.HandleTunnelBuildReply(vtbr)
		}

	case i2np.TypeGarlic:
		r.garlicHandler.HandleGarlicMessage(msg.Payload())

	case i2np.TypeDeliveryStatus:
		// Handle delivery confirmation
	}

	// Notify callback
	if r.onMessageReceived != nil {
		r.onMessageReceived(msg)
	}
}

// onLocalDelivery handles messages delivered locally.
func (r *Router) onLocalDelivery(msg *i2np.RawMessage) {
	r.processMessage(&routerMessage{msg: msg})
}

// onRouterDelivery handles messages to be sent to a router.
func (r *Router) onRouterDelivery(dest data.Hash, msg *i2np.RawMessage) {
	r.sendI2NPMessage(dest, msg)
}

// onTunnelDelivery handles messages to be sent via tunnel.
func (r *Router) onTunnelDelivery(tunnelID uint32, gateway data.Hash, msg *i2np.RawMessage) {
	// Create TunnelGateway message
	tgMsg := i2np.NewTunnelGateway(tunnelID, msg.ToBytes())
	r.sendI2NPMessage(gateway, tgMsg.ToRawMessage())
}

// maintenanceLoop performs periodic maintenance tasks.
func (r *Router) maintenanceLoop() {
	riTicker := time.NewTicker(10 * time.Minute)
	defer riTicker.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-riTicker.C:
			r.publishRouterInfo()
		}
	}
}

// SelectPeers implements tunnel.PeerSelector.
func (r *Router) SelectPeers(count int, exclude []data.Hash) ([]data.Hash, error) {
	routers := r.netDb.RandomRouters(count*2, exclude)
	if len(routers) < count {
		return nil, errors.New("router: not enough peers")
	}

	result := make([]data.Hash, 0, count)
	for _, ri := range routers {
		if len(result) >= count {
			break
		}
		result = append(result, ri.GetIdentHash())
	}

	return result, nil
}

// setState sets the router state.
func (r *Router) setState(state int) {
	r.mu.Lock()
	r.state = state
	r.mu.Unlock()
}

// State returns the current router state.
func (r *Router) State() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.state
}

// IsRunning returns true if the router is running.
func (r *Router) IsRunning() bool {
	return r.State() == RouterStateRunning
}

// Context returns the router context.
func (r *Router) Context() *Context {
	return r.context
}

// NetDb returns the network database.
func (r *Router) NetDb() *netdb.NetDb {
	return r.netDb
}

// TunnelManager returns the tunnel manager.
func (r *Router) TunnelManager() *tunnel.Manager {
	return r.tunnelManager
}

// SetMessageCallback sets the message callback.
func (r *Router) SetMessageCallback(cb func(*i2np.RawMessage)) {
	r.onMessageReceived = cb
}

// Stats returns router statistics.
func (r *Router) Stats() *RouterStats {
	var ntcp2Sessions, ssu2Sessions int

	if r.ntcp2Server != nil {
		ntcp2Sessions = r.ntcp2Server.SessionCount()
	}
	if r.ssu2Server != nil {
		ssu2Sessions = r.ssu2Server.SessionCount()
	}

	tunnelStats := r.tunnelManager.Stats()

	return &RouterStats{
		State:          r.State(),
		RouterInfos:    r.netDb.RouterInfoCount(),
		LeaseSets:      r.netDb.LeaseSetCount(),
		Floodfills:     r.netDb.FloodfillCount(),
		NTCP2Sessions:  ntcp2Sessions,
		SSU2Sessions:   ssu2Sessions,
		InboundTunnels: tunnelStats.ExploratoryInbound + tunnelStats.ClientInbound,
		OutboundTunnels: tunnelStats.ExploratoryOutbound + tunnelStats.ClientOutbound,
		TransitTunnels: tunnelStats.TransitCount,
	}
}

// RouterStats contains router statistics.
type RouterStats struct {
	State           int
	RouterInfos     int
	LeaseSets       int
	Floodfills      int
	NTCP2Sessions   int
	SSU2Sessions    int
	InboundTunnels  int
	OutboundTunnels int
	TransitTunnels  int
}
