package tunnel

import (
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/debug"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

var log = debug.NewLogger(debug.SubTunnel)

// Manager coordinates all tunnel operations.
type Manager struct {
	mu sync.RWMutex

	localIdentity data.Hash

	builder        *Builder
	exploratoryPool *Pool
	clientPools    map[data.Hash]*Pool

	transitTunnels map[TunnelID]*TransitTunnel

	peerSelector PeerSelector

	onSendMessage func(dest data.Hash, msg *i2np.RawMessage) error

	running bool
	done    chan struct{}
}

// NewManager creates a new tunnel manager.
func NewManager(localIdentity data.Hash) *Manager {
	builder := NewBuilder(localIdentity)

	m := &Manager{
		localIdentity:  localIdentity,
		builder:        builder,
		clientPools:    make(map[data.Hash]*Pool),
		transitTunnels: make(map[TunnelID]*TransitTunnel),
		done:           make(chan struct{}),
	}

	return m
}

// SetMessageSender sets the function for sending I2NP messages.
func (m *Manager) SetMessageSender(sender func(dest data.Hash, msg *i2np.RawMessage) error) {
	m.onSendMessage = sender
	m.builder.SetMessageSender(sender)
}

// SetPeerSelector sets the peer selector for tunnel building.
func (m *Manager) SetPeerSelector(selector PeerSelector) {
	m.peerSelector = selector
}

// Start starts the tunnel manager.
func (m *Manager) Start() error {
	defer log.FuncEntry()()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		log.Debug("tunnel manager already running")
		return nil
	}

	// Create exploratory pool
	if m.peerSelector != nil {
		log.Info("creating exploratory tunnel pool")
		m.exploratoryPool = NewPool(ExploratoryPoolConfig(), m.builder, m.peerSelector)
		m.exploratoryPool.Start()
	}

	m.running = true
	log.Info("tunnel manager started")

	// Start maintenance
	go m.maintenance()

	return nil
}

// Stop stops the tunnel manager.
func (m *Manager) Stop() {
	defer log.FuncEntry()()

	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		log.Debug("tunnel manager not running")
		return
	}
	m.running = false
	close(m.done)
	m.mu.Unlock()

	// Stop exploratory pool
	if m.exploratoryPool != nil {
		log.Debug("stopping exploratory pool")
		m.exploratoryPool.Stop()
	}

	// Stop all client pools
	m.mu.RLock()
	poolCount := len(m.clientPools)
	for dest, pool := range m.clientPools {
		log.Debug("stopping client pool for %x...", dest[:8])
		pool.Stop()
	}
	m.mu.RUnlock()

	log.Info("tunnel manager stopped (stopped %d client pools)", poolCount)
}

// CreateClientPool creates a tunnel pool for a client destination.
func (m *Manager) CreateClientPool(destination data.Hash, config *PoolConfig) *Pool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if pool already exists
	if pool, ok := m.clientPools[destination]; ok {
		return pool
	}

	config.Destination = &destination
	pool := NewPool(config, m.builder, m.peerSelector)

	m.clientPools[destination] = pool

	if m.running {
		pool.Start()
	}

	return pool
}

// GetClientPool returns the tunnel pool for a destination.
func (m *Manager) GetClientPool(destination data.Hash) *Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clientPools[destination]
}

// RemoveClientPool removes a client tunnel pool.
func (m *Manager) RemoveClientPool(destination data.Hash) {
	m.mu.Lock()
	pool, ok := m.clientPools[destination]
	if ok {
		delete(m.clientPools, destination)
	}
	m.mu.Unlock()

	if pool != nil {
		pool.Stop()
	}
}

// GetExploratoryPool returns the exploratory tunnel pool.
func (m *Manager) GetExploratoryPool() *Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.exploratoryPool
}

// GetExploratoryInbound returns an inbound exploratory tunnel.
func (m *Manager) GetExploratoryInbound() *InboundTunnel {
	m.mu.RLock()
	pool := m.exploratoryPool
	m.mu.RUnlock()

	if pool == nil {
		return nil
	}
	return pool.GetInbound()
}

// GetExploratoryOutbound returns an outbound exploratory tunnel.
func (m *Manager) GetExploratoryOutbound() *OutboundTunnel {
	m.mu.RLock()
	pool := m.exploratoryPool
	m.mu.RUnlock()

	if pool == nil {
		return nil
	}
	return pool.GetOutbound()
}

// HandleTunnelBuild handles an incoming tunnel build request.
func (m *Manager) HandleTunnelBuild(msg *i2np.VariableTunnelBuild) error {
	log.Trace("handling tunnel build request with %d records", len(msg.Records))

	// Find which record is for us
	for i, record := range msg.Records {
		// Check if this record is for us (ToPeer matches our identity)
		if !m.isRecordForUs(record) {
			continue
		}

		log.Debug("processing build record %d (for us)", i)

		// Decrypt and process the record
		transit, replyRecord, err := m.processOurRecord(record)
		if err != nil {
			log.Warn("failed to process build record: %v", err)
			// Create rejection reply
			replyRecord = m.createRejectionReply(TunnelBuildReplyCritical)
		}

		// Replace record with reply
		msg.Records[i] = m.recordToReplyRecord(record, replyRecord)

		if transit != nil {
			// Store transit tunnel
			m.mu.Lock()
			m.transitTunnels[transit.receiveTunnelID] = transit
			m.mu.Unlock()
			log.Info("created transit tunnel ID=%d -> %d", transit.receiveTunnelID, transit.sendTunnelID)
		}

		// Forward to next hop or send reply
		return m.forwardBuildMessage(msg, transit)
	}

	// No record for us, just forward
	log.Trace("no build record for us, forwarding")
	return m.forwardBuildMessage(msg, nil)
}

// isRecordForUs checks if a build record is addressed to us.
func (m *Manager) isRecordForUs(record *i2np.TunnelBuildRecord) bool {
	// Compare ToPeer with our identity
	for i := 0; i < 16; i++ {
		if record.ToPeer[i] != m.localIdentity[i] {
			return false
		}
	}
	return true
}

// processOurRecord decrypts and processes a build record for us.
func (m *Manager) processOurRecord(record *i2np.TunnelBuildRecord) (*TransitTunnel, *TunnelBuildReplyRecord, error) {
	// TODO: Decrypt using our encryption key
	// For now, use the encrypted data directly (placeholder)
	recordData := record.EncryptedData

	// Create transit tunnel
	buildRecord := &TunnelBuildRecord{}
	transit, err := CreateTransitTunnel(buildRecord, recordData)
	if err != nil {
		return nil, nil, err
	}

	// Create acceptance reply
	reply := &TunnelBuildReplyRecord{
		Reply: TunnelBuildReplyAccepted,
	}

	return transit, reply, nil
}

// createRejectionReply creates a rejection reply record.
func (m *Manager) createRejectionReply(reason uint8) *TunnelBuildReplyRecord {
	return &TunnelBuildReplyRecord{
		Reply: reason,
	}
}

// recordToReplyRecord converts a build record to a reply record for the response.
func (m *Manager) recordToReplyRecord(original *i2np.TunnelBuildRecord, reply *TunnelBuildReplyRecord) *i2np.TunnelBuildRecord {
	// The reply replaces the encrypted data with the reply
	result := &i2np.TunnelBuildRecord{}
	copy(result.ToPeer[:], original.ToPeer[:])

	// Encrypt reply with reply key
	// TODO: Implement proper encryption
	replyData := make([]byte, len(original.EncryptedData))
	replyData[0] = reply.Reply
	result.EncryptedData = replyData

	return result
}

// forwardBuildMessage forwards a build message to the next hop.
func (m *Manager) forwardBuildMessage(msg *i2np.VariableTunnelBuild, transit *TransitTunnel) error {
	if m.onSendMessage == nil {
		return nil
	}

	if transit != nil && !transit.isEndpoint {
		// Forward to next router
		return m.onSendMessage(transit.nextRouter, msg.ToRawMessage())
	}

	// This is the endpoint, need to send reply back
	// The reply goes through a different path
	return nil
}

// HandleTunnelBuildReply handles an incoming tunnel build reply.
func (m *Manager) HandleTunnelBuildReply(msg *i2np.VariableTunnelBuildReply) error {
	return m.builder.HandleBuildReply(msg)
}

// HandleTunnelData handles incoming tunnel data.
func (m *Manager) HandleTunnelData(tunnelID TunnelID, data []byte) error {
	log.Trace("handling tunnel data for ID=%d (%d bytes)", tunnelID, len(data))

	m.mu.RLock()
	transit, ok := m.transitTunnels[tunnelID]
	m.mu.RUnlock()

	if ok {
		// Process as transit
		log.Trace("forwarding as transit tunnel ID=%d -> %d", tunnelID, transit.sendTunnelID)
		processed, err := transit.HandleData(data)
		if err != nil {
			log.Error("failed to process transit data: %v", err)
			return err
		}

		// Forward to next hop
		if m.onSendMessage != nil {
			// Create TunnelData message
			tdMsg := i2np.NewTunnelData(uint32(transit.sendTunnelID), processed)
			return m.onSendMessage(transit.nextRouter, tdMsg.ToRawMessage())
		}
		return nil
	}

	// Check if it's for one of our inbound tunnels
	// This would be handled by the pool that owns the tunnel
	log.Trace("no transit tunnel found for ID=%d", tunnelID)
	return nil
}

// GetTransitTunnel returns a transit tunnel by ID.
func (m *Manager) GetTransitTunnel(tunnelID TunnelID) *TransitTunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.transitTunnels[tunnelID]
}

// TransitTunnelCount returns the number of transit tunnels.
func (m *Manager) TransitTunnelCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.transitTunnels)
}

// maintenance performs periodic manager maintenance.
func (m *Manager) maintenance() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.cleanupExpiredTransit()
		}
	}
}

// cleanupExpiredTransit removes expired transit tunnels.
func (m *Manager) cleanupExpiredTransit() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, transit := range m.transitTunnels {
		if transit.IsExpired() {
			delete(m.transitTunnels, id)
		}
	}
}

// Stats returns tunnel statistics.
func (m *Manager) Stats() *TunnelStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &TunnelStats{
		TransitCount: len(m.transitTunnels),
	}

	if m.exploratoryPool != nil {
		stats.ExploratoryInbound = m.exploratoryPool.ActiveInboundCount()
		stats.ExploratoryOutbound = m.exploratoryPool.ActiveOutboundCount()
	}

	for _, pool := range m.clientPools {
		stats.ClientInbound += pool.ActiveInboundCount()
		stats.ClientOutbound += pool.ActiveOutboundCount()
	}

	return stats
}

// TunnelStats contains tunnel statistics.
type TunnelStats struct {
	ExploratoryInbound  int
	ExploratoryOutbound int
	ClientInbound       int
	ClientOutbound      int
	TransitCount        int
}
