package router

import (
	"time"
)

// Config holds the router configuration.
type Config struct {
	// Data directory for persistent storage
	DataDir string

	// Network settings
	NTCP2Addr    string // NTCP2 listen address (e.g., "0.0.0.0:9001")
	SSU2Addr     string // SSU2 listen address (e.g., "0.0.0.0:9001")
	NTCP2AddrV6  string // NTCP2 IPv6 address
	SSU2AddrV6   string // SSU2 IPv6 address

	// External addresses (for NAT)
	ExternalNTCP2 string
	ExternalSSU2  string

	// Bandwidth limits (KB/s)
	BandwidthIn   int
	BandwidthOut  int
	BandwidthShare int // Percentage to share (0-100)

	// Router identity
	IdentityPath string // Path to router identity file

	// Floodfill settings
	Floodfill bool // Operate as a floodfill router

	// Reseed settings
	ReseedHosts []string // Custom reseed hosts

	// Tunnel settings
	InboundTunnelLength  int
	OutboundTunnelLength int
	InboundTunnelCount   int
	OutboundTunnelCount  int

	// Timeouts
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration

	// Logging
	LogLevel string
}

// DefaultConfig returns the default router configuration.
func DefaultConfig() *Config {
	return &Config{
		DataDir:              "~/.i2p-go",
		NTCP2Addr:            "0.0.0.0:9001",
		SSU2Addr:             "0.0.0.0:9001",
		BandwidthIn:          256,
		BandwidthOut:         256,
		BandwidthShare:       80,
		IdentityPath:         "router.keys.dat",
		Floodfill:            false,
		InboundTunnelLength:  3,
		OutboundTunnelLength: 3,
		InboundTunnelCount:   2,
		OutboundTunnelCount:  2,
		HandshakeTimeout:     10 * time.Second,
		IdleTimeout:          2 * time.Minute,
		LogLevel:             "info",
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		c.DataDir = "~/.i2p-go"
	}

	if c.InboundTunnelLength < 0 || c.InboundTunnelLength > 8 {
		c.InboundTunnelLength = 3
	}

	if c.OutboundTunnelLength < 0 || c.OutboundTunnelLength > 8 {
		c.OutboundTunnelLength = 3
	}

	if c.InboundTunnelCount < 1 {
		c.InboundTunnelCount = 2
	}

	if c.OutboundTunnelCount < 1 {
		c.OutboundTunnelCount = 2
	}

	return nil
}
