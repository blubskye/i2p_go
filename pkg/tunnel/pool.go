package tunnel

import (
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// PoolConfig configures a tunnel pool.
type PoolConfig struct {
	Name           string
	NumInbound     int           // Number of inbound tunnels to maintain
	NumOutbound    int           // Number of outbound tunnels to maintain
	InboundLength  int           // Number of hops in inbound tunnels
	OutboundLength int           // Number of hops in outbound tunnels
	Destination    *data.Hash    // For client pools (nil for exploratory)
	IsExploratory  bool          // Is this the exploratory pool?
}

// DefaultPoolConfig returns default pool configuration.
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		Name:           "default",
		NumInbound:     2,
		NumOutbound:    2,
		InboundLength:  DefaultTunnelHops,
		OutboundLength: DefaultTunnelHops,
		IsExploratory:  false,
	}
}

// ExploratoryPoolConfig returns configuration for the exploratory pool.
func ExploratoryPoolConfig() *PoolConfig {
	return &PoolConfig{
		Name:           "exploratory",
		NumInbound:     2,
		NumOutbound:    2,
		InboundLength:  2,
		OutboundLength: 2,
		IsExploratory:  true,
	}
}

// Pool manages a set of tunnels for a destination.
type Pool struct {
	mu sync.RWMutex

	config *PoolConfig

	inbound      []*InboundTunnel
	outbound     []*OutboundTunnel

	builder      *Builder
	peerSelector PeerSelector

	running bool
	done    chan struct{}

	onTunnelReady    func(Tunnel)
	onTunnelExpired  func(Tunnel)
}

// PeerSelector selects peers for tunnel hops.
type PeerSelector interface {
	SelectPeers(count int, exclude []data.Hash) ([]data.Hash, error)
}

// NewPool creates a new tunnel pool.
func NewPool(config *PoolConfig, builder *Builder, peerSelector PeerSelector) *Pool {
	return &Pool{
		config:       config,
		inbound:      make([]*InboundTunnel, 0, config.NumInbound),
		outbound:     make([]*OutboundTunnel, 0, config.NumOutbound),
		builder:      builder,
		peerSelector: peerSelector,
		done:         make(chan struct{}),
	}
}

// Start starts the tunnel pool.
func (p *Pool) Start() {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.mu.Unlock()

	// Initial tunnel builds
	p.buildTunnels()

	// Start maintenance loop
	go p.maintenance()
}

// Stop stops the tunnel pool.
func (p *Pool) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	close(p.done)
	p.mu.Unlock()
}

// GetInbound returns an available inbound tunnel.
func (p *Pool) GetInbound() *InboundTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, t := range p.inbound {
		if t.GetState() == TunnelStateEstablished && !t.IsExpired() {
			return t
		}
	}
	return nil
}

// GetOutbound returns an available outbound tunnel.
func (p *Pool) GetOutbound() *OutboundTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, t := range p.outbound {
		if t.GetState() == TunnelStateEstablished && !t.IsExpired() {
			return t
		}
	}
	return nil
}

// GetAllInbound returns all inbound tunnels.
func (p *Pool) GetAllInbound() []*InboundTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*InboundTunnel, len(p.inbound))
	copy(result, p.inbound)
	return result
}

// GetAllOutbound returns all outbound tunnels.
func (p *Pool) GetAllOutbound() []*OutboundTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*OutboundTunnel, len(p.outbound))
	copy(result, p.outbound)
	return result
}

// ActiveInboundCount returns the number of active inbound tunnels.
func (p *Pool) ActiveInboundCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, t := range p.inbound {
		if t.GetState() == TunnelStateEstablished && !t.IsExpired() {
			count++
		}
	}
	return count
}

// ActiveOutboundCount returns the number of active outbound tunnels.
func (p *Pool) ActiveOutboundCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, t := range p.outbound {
		if t.GetState() == TunnelStateEstablished && !t.IsExpired() {
			count++
		}
	}
	return count
}

// SetCallbacks sets the tunnel event callbacks.
func (p *Pool) SetCallbacks(onReady, onExpired func(Tunnel)) {
	p.mu.Lock()
	p.onTunnelReady = onReady
	p.onTunnelExpired = onExpired
	p.mu.Unlock()
}

// buildTunnels builds tunnels to reach the configured quantity.
func (p *Pool) buildTunnels() {
	p.mu.RLock()
	numInbound := p.ActiveInboundCount()
	numOutbound := p.ActiveOutboundCount()
	needInbound := p.config.NumInbound - numInbound
	needOutbound := p.config.NumOutbound - numOutbound
	p.mu.RUnlock()

	// Build inbound tunnels
	for i := 0; i < needInbound; i++ {
		go p.buildInboundTunnel()
	}

	// Build outbound tunnels
	for i := 0; i < needOutbound; i++ {
		go p.buildOutboundTunnel()
	}
}

// buildInboundTunnel builds a single inbound tunnel.
func (p *Pool) buildInboundTunnel() {
	if p.peerSelector == nil {
		return
	}

	// Select peers for the tunnel
	peers, err := p.peerSelector.SelectPeers(p.config.InboundLength, nil)
	if err != nil || len(peers) == 0 {
		return
	}

	// Build the tunnel
	err = p.builder.BuildTunnel(TunnelTypeInbound, peers, func(t Tunnel, err error) {
		if err != nil {
			return
		}

		inbound, ok := t.(*InboundTunnel)
		if !ok {
			return
		}

		p.mu.Lock()
		p.inbound = append(p.inbound, inbound)
		callback := p.onTunnelReady
		p.mu.Unlock()

		if callback != nil {
			callback(inbound)
		}
	})

	if err != nil {
		// Build failed to start
	}
}

// buildOutboundTunnel builds a single outbound tunnel.
func (p *Pool) buildOutboundTunnel() {
	if p.peerSelector == nil {
		return
	}

	// Select peers for the tunnel
	peers, err := p.peerSelector.SelectPeers(p.config.OutboundLength, nil)
	if err != nil || len(peers) == 0 {
		return
	}

	// Build the tunnel
	err = p.builder.BuildTunnel(TunnelTypeOutbound, peers, func(t Tunnel, err error) {
		if err != nil {
			return
		}

		outbound, ok := t.(*OutboundTunnel)
		if !ok {
			return
		}

		p.mu.Lock()
		p.outbound = append(p.outbound, outbound)
		callback := p.onTunnelReady
		p.mu.Unlock()

		if callback != nil {
			callback(outbound)
		}
	})

	if err != nil {
		// Build failed to start
	}
}

// maintenance performs periodic pool maintenance.
func (p *Pool) maintenance() {
	buildTicker := time.NewTicker(30 * time.Second)
	cleanupTicker := time.NewTicker(10 * time.Second)
	defer buildTicker.Stop()
	defer cleanupTicker.Stop()

	for {
		select {
		case <-p.done:
			return

		case <-buildTicker.C:
			p.buildTunnels()

		case <-cleanupTicker.C:
			p.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired tunnels.
func (p *Pool) cleanupExpired() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Cleanup expired inbound tunnels
	activeInbound := make([]*InboundTunnel, 0, len(p.inbound))
	for _, t := range p.inbound {
		if t.IsExpired() {
			if p.onTunnelExpired != nil {
				go p.onTunnelExpired(t)
			}
		} else {
			activeInbound = append(activeInbound, t)
		}
	}
	p.inbound = activeInbound

	// Cleanup expired outbound tunnels
	activeOutbound := make([]*OutboundTunnel, 0, len(p.outbound))
	for _, t := range p.outbound {
		if t.IsExpired() {
			if p.onTunnelExpired != nil {
				go p.onTunnelExpired(t)
			}
		} else {
			activeOutbound = append(activeOutbound, t)
		}
	}
	p.outbound = activeOutbound
}

// Config returns the pool configuration.
func (p *Pool) Config() *PoolConfig {
	return p.config
}

// Name returns the pool name.
func (p *Pool) Name() string {
	return p.config.Name
}

// IsExploratory returns true if this is the exploratory pool.
func (p *Pool) IsExploratory() bool {
	return p.config.IsExploratory
}
