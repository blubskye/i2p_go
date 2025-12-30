package sam

import (
	"sync"

	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/streaming"
)

// Session represents a SAM session.
type Session struct {
	mu sync.RWMutex

	ID            string
	Style         string
	Keys          *data.PrivateKeys
	streamManager *streaming.Manager
	client        *Client
	server        *Server
	closed        bool
}

// Close closes the session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.streamManager != nil {
		s.streamManager.Close()
	}

	return nil
}

// GetDestination returns the session's destination.
func (s *Session) GetDestination() *data.Destination {
	return data.NewDestinationFromIdentity(s.Keys.Identity)
}

// GetHash returns the session's identity hash.
func (s *Session) GetHash() data.IdentHash {
	return s.Keys.GetIdentHash()
}

// GetBase64 returns the destination as Base64.
func (s *Session) GetBase64() string {
	return data.Base64Encode(s.Keys.Identity.ToBuffer())
}

// IsStream returns true if this is a stream session.
func (s *Session) IsStream() bool {
	return s.Style == StyleStream
}

// IsDatagram returns true if this is a datagram session.
func (s *Session) IsDatagram() bool {
	return s.Style == StyleDatagram
}

// IsRaw returns true if this is a raw session.
func (s *Session) IsRaw() bool {
	return s.Style == StyleRaw
}
