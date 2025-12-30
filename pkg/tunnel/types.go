// Package tunnel implements the I2P tunnel system.
// Tunnels are unidirectional encrypted pathways through multiple routers.
package tunnel

import (
	"errors"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Tunnel constants
const (
	TunnelDataSize     = 1028 // TunnelID (4) + Data (1024)
	TunnelPayloadSize  = 1024
	IVSize             = 16
	MaxTunnelHops      = 8
	DefaultTunnelHops  = 3
	TunnelBuildTimeout = 30 * time.Second
	TunnelExpiration   = 10 * time.Minute
	TunnelRenewal      = 9 * time.Minute // Start renewal before expiration
)

// TunnelType represents the type of tunnel.
type TunnelType int

const (
	TunnelTypeInbound  TunnelType = iota // Inbound tunnel (receives messages)
	TunnelTypeOutbound                   // Outbound tunnel (sends messages)
	TunnelTypeTransit                    // Transit tunnel (forwards messages)
)

// TunnelState represents the current state of a tunnel.
type TunnelState int

const (
	TunnelStateBuilding   TunnelState = iota // Being built
	TunnelStateEstablished                    // Active and usable
	TunnelStateExpiring                       // About to expire
	TunnelStateExpired                        // Expired
	TunnelStateFailed                         // Failed to build
)

// TunnelID represents a 4-byte tunnel identifier.
type TunnelID uint32

// HopConfig represents the configuration for a single tunnel hop.
type HopConfig struct {
	RouterHash     data.Hash  // Router identity hash
	TunnelID       TunnelID   // Tunnel ID at this hop
	NextTunnelID   TunnelID   // Tunnel ID for next hop
	NextRouter     data.Hash  // Next router in the tunnel
	LayerKey       [32]byte   // AES layer encryption key
	IVKey          [32]byte   // IV encryption key
	ReplyKey       [32]byte   // Reply key for build responses
	ReplyIV        [16]byte   // Reply IV for build responses
	IsGateway      bool       // Is this the gateway (first hop)?
	IsEndpoint     bool       // Is this the endpoint (last hop)?
}

// TunnelConfig represents the full configuration for a tunnel.
type TunnelConfig struct {
	Type           TunnelType
	Hops           []*HopConfig
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ReceiveTunnelID TunnelID   // For inbound: our receiving tunnel ID
	SendTunnelID   TunnelID   // For outbound: first hop's tunnel ID
	Gateway        data.Hash  // For inbound: gateway router
	Endpoint       data.Hash  // For outbound: endpoint router
}

// Tunnel is the base interface for all tunnel types.
type Tunnel interface {
	GetType() TunnelType
	GetState() TunnelState
	GetTunnelID() TunnelID
	GetConfig() *TunnelConfig
	IsExpired() bool
	HandleData(data []byte) ([]byte, error)
}

// InboundTunnel represents an inbound tunnel that receives messages.
type InboundTunnel struct {
	config    *TunnelConfig
	state     TunnelState
	tunnelID  TunnelID      // Our receiving tunnel ID
	keys      [][32]byte    // Decryption keys (in reverse order)
	ivKeys    [][32]byte    // IV keys (in reverse order)
}

// OutboundTunnel represents an outbound tunnel that sends messages.
type OutboundTunnel struct {
	config    *TunnelConfig
	state     TunnelState
	tunnelID  TunnelID      // First hop's tunnel ID
	gateway   data.Hash     // First hop's router hash
	keys      [][32]byte    // Encryption keys
	ivKeys    [][32]byte    // IV keys
}

// TransitTunnel represents a tunnel we participate in as a transit hop.
type TransitTunnel struct {
	receiveTunnelID TunnelID
	sendTunnelID    TunnelID
	nextRouter      data.Hash
	layerKey        [32]byte
	ivKey           [32]byte
	isGateway       bool
	isEndpoint      bool
	createdAt       time.Time
	expiresAt       time.Time
}

// Errors
var (
	ErrTunnelExpired      = errors.New("tunnel: tunnel expired")
	ErrTunnelNotReady     = errors.New("tunnel: tunnel not ready")
	ErrTunnelBuildFailed  = errors.New("tunnel: build failed")
	ErrTunnelBuildTimeout = errors.New("tunnel: build timeout")
	ErrInvalidTunnelData  = errors.New("tunnel: invalid tunnel data")
	ErrDecryptionFailed   = errors.New("tunnel: decryption failed")
)

// TunnelBuildRecord represents a build record for one hop.
type TunnelBuildRecord struct {
	ToPeer        data.Hash  // First 16 bytes encrypted with AES
	TunnelID      TunnelID
	NextTunnelID  TunnelID
	NextRouter    data.Hash
	LayerKey      [32]byte
	IVKey         [32]byte
	ReplyKey      [32]byte
	ReplyIV       [16]byte
	Flags         uint8      // Gateway (0x80) and Endpoint (0x40) flags
	RequestTime   uint32     // Unix timestamp
	SendMsgID     uint32     // Message ID for response
}

// TunnelBuildReplyRecord represents a reply record from one hop.
type TunnelBuildReplyRecord struct {
	Reply         uint8      // 0 = accepted, other = reject reason
	RandomPadding [511]byte  // Random padding (for standard records)
}

// Reply codes
const (
	TunnelBuildReplyAccepted         = 0
	TunnelBuildReplyProbabilistic    = 10
	TunnelBuildReplyBandwidth        = 20
	TunnelBuildReplyCritical         = 30
)

// NewInboundTunnel creates a new inbound tunnel.
func NewInboundTunnel(config *TunnelConfig) *InboundTunnel {
	// Extract keys in reverse order for decryption
	keys := make([][32]byte, len(config.Hops))
	ivKeys := make([][32]byte, len(config.Hops))
	for i, hop := range config.Hops {
		keys[len(config.Hops)-1-i] = hop.LayerKey
		ivKeys[len(config.Hops)-1-i] = hop.IVKey
	}

	return &InboundTunnel{
		config:   config,
		state:    TunnelStateBuilding,
		tunnelID: config.ReceiveTunnelID,
		keys:     keys,
		ivKeys:   ivKeys,
	}
}

// NewOutboundTunnel creates a new outbound tunnel.
func NewOutboundTunnel(config *TunnelConfig) *OutboundTunnel {
	keys := make([][32]byte, len(config.Hops))
	ivKeys := make([][32]byte, len(config.Hops))
	for i, hop := range config.Hops {
		keys[i] = hop.LayerKey
		ivKeys[i] = hop.IVKey
	}

	return &OutboundTunnel{
		config:   config,
		state:    TunnelStateBuilding,
		tunnelID: config.SendTunnelID,
		gateway:  config.Gateway,
		keys:     keys,
		ivKeys:   ivKeys,
	}
}

// NewTransitTunnel creates a new transit tunnel.
func NewTransitTunnel(receiveTunnelID, sendTunnelID TunnelID, nextRouter data.Hash, layerKey, ivKey [32]byte, isGateway, isEndpoint bool) *TransitTunnel {
	return &TransitTunnel{
		receiveTunnelID: receiveTunnelID,
		sendTunnelID:    sendTunnelID,
		nextRouter:      nextRouter,
		layerKey:        layerKey,
		ivKey:           ivKey,
		isGateway:       isGateway,
		isEndpoint:      isEndpoint,
		createdAt:       time.Now(),
		expiresAt:       time.Now().Add(TunnelExpiration),
	}
}

// GetType returns the tunnel type.
func (t *InboundTunnel) GetType() TunnelType { return TunnelTypeInbound }
func (t *OutboundTunnel) GetType() TunnelType { return TunnelTypeOutbound }
func (t *TransitTunnel) GetType() TunnelType { return TunnelTypeTransit }

// GetState returns the tunnel state.
func (t *InboundTunnel) GetState() TunnelState { return t.state }
func (t *OutboundTunnel) GetState() TunnelState { return t.state }

// GetTunnelID returns the tunnel ID.
func (t *InboundTunnel) GetTunnelID() TunnelID { return t.tunnelID }
func (t *OutboundTunnel) GetTunnelID() TunnelID { return t.tunnelID }
func (t *TransitTunnel) GetTunnelID() TunnelID { return t.receiveTunnelID }

// GetConfig returns the tunnel configuration.
func (t *InboundTunnel) GetConfig() *TunnelConfig { return t.config }
func (t *OutboundTunnel) GetConfig() *TunnelConfig { return t.config }

// IsExpired returns true if the tunnel has expired.
func (t *InboundTunnel) IsExpired() bool { return time.Now().After(t.config.ExpiresAt) }
func (t *OutboundTunnel) IsExpired() bool { return time.Now().After(t.config.ExpiresAt) }
func (t *TransitTunnel) IsExpired() bool { return time.Now().After(t.expiresAt) }

// SetEstablished marks the tunnel as established.
func (t *InboundTunnel) SetEstablished() {
	t.state = TunnelStateEstablished
	t.config.CreatedAt = time.Now()
	t.config.ExpiresAt = time.Now().Add(TunnelExpiration)
}

func (t *OutboundTunnel) SetEstablished() {
	t.state = TunnelStateEstablished
	t.config.CreatedAt = time.Now()
	t.config.ExpiresAt = time.Now().Add(TunnelExpiration)
}

// Gateway returns the gateway router hash (for outbound).
func (t *OutboundTunnel) Gateway() data.Hash { return t.gateway }

// HopCount returns the number of hops in the tunnel.
func (t *InboundTunnel) HopCount() int { return len(t.config.Hops) }
func (t *OutboundTunnel) HopCount() int { return len(t.config.Hops) }
