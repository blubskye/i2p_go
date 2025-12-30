package ssu2

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

// Server manages SSU2 connections.
type Server struct {
	mu sync.RWMutex

	conn       *net.UDPConn
	connV6     *net.UDPConn
	localAddr  string
	localAddr6 string

	localIdentity  []byte
	localStaticKey *crypto.X25519Keys

	sessions map[uint64]*Session // ConnID -> Session

	running bool
	done    chan struct{}

	onSession func(*Session)
	onMessage func(*Session, *i2np.RawMessage)
}

// ServerConfig contains configuration for the SSU2 server.
type ServerConfig struct {
	ListenAddr     string // IPv4 address:port
	ListenAddrV6   string // IPv6 address:port
	LocalIdentity  []byte
	LocalStaticKey *crypto.X25519Keys
	OnSession      func(*Session)
	OnMessage      func(*Session, *i2np.RawMessage)
}

// NewServer creates a new SSU2 server.
func NewServer(config *ServerConfig) *Server {
	return &Server{
		localAddr:      config.ListenAddr,
		localAddr6:     config.ListenAddrV6,
		localIdentity:  config.LocalIdentity,
		localStaticKey: config.LocalStaticKey,
		sessions:       make(map[uint64]*Session),
		done:           make(chan struct{}),
		onSession:      config.OnSession,
		onMessage:      config.OnMessage,
	}
}

// Start starts the SSU2 server.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	// Start IPv4 listener
	if s.localAddr != "" {
		addr, err := net.ResolveUDPAddr("udp4", s.localAddr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return err
		}
		s.conn = conn
		go s.readLoop(conn)
	}

	// Start IPv6 listener
	if s.localAddr6 != "" {
		addr, err := net.ResolveUDPAddr("udp6", s.localAddr6)
		if err != nil {
			if s.conn != nil {
				s.conn.Close()
			}
			return err
		}
		conn, err := net.ListenUDP("udp6", addr)
		if err != nil {
			if s.conn != nil {
				s.conn.Close()
			}
			return err
		}
		s.connV6 = conn
		go s.readLoop(conn)
	}

	s.running = true

	// Start maintenance routines
	go s.maintenance()

	return nil
}

// Stop stops the SSU2 server.
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	// Close connections
	if s.conn != nil {
		s.conn.Close()
	}
	if s.connV6 != nil {
		s.connV6.Close()
	}

	// Terminate all sessions
	s.mu.RLock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.RUnlock()

	for _, session := range sessions {
		session.Terminate(TermRouterShutdown)
	}
}

// readLoop reads incoming packets.
func (s *Server) readLoop(conn *net.UDPConn) {
	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		// Copy packet data
		packet := make([]byte, n)
		copy(packet, buf[:n])

		go s.handlePacket(conn, remoteAddr, packet)
	}
}

// handlePacket handles an incoming packet.
func (s *Server) handlePacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	if len(data) < ShortHeaderSize {
		return
	}

	// Parse header to get connection ID
	header, err := ParseHeader(data)
	if err != nil {
		return
	}

	// Find or create session
	s.mu.RLock()
	session := s.sessions[header.DestConnID]
	s.mu.RUnlock()

	if session == nil {
		// Check if this is a SessionRequest
		if header.Type == MsgSessionRequest {
			s.handleNewSession(conn, remoteAddr, data, header)
			return
		}
		// Unknown session
		return
	}

	// Process packet in existing session
	session.ProcessPacket(data)
}

// handleNewSession handles a new incoming session.
func (s *Server) handleNewSession(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte, header *Header) {
	// Create new session
	session, err := NewSession(&SessionConfig{
		Conn:           conn,
		RemoteAddr:     remoteAddr,
		LocalIdentity:  s.localIdentity,
		LocalStaticKey: s.localStaticKey,
		OnMessage:      s.createMessageHandler(),
		OnTerminate:    s.createTerminateHandler(header.DestConnID),
	})
	if err != nil {
		return
	}

	// Store remote conn ID from the source (it's in dest for SessionRequest)
	session.remoteConnID = header.DestConnID

	// Add to sessions
	s.mu.Lock()
	s.sessions[session.localConnID] = session
	s.mu.Unlock()

	// Process the SessionRequest
	if err := session.handleSessionRequest(data); err != nil {
		s.mu.Lock()
		delete(s.sessions, session.localConnID)
		s.mu.Unlock()
		return
	}

	// Notify callback
	if s.onSession != nil {
		s.onSession(session)
	}
}

// Connect initiates an outbound connection.
func (s *Server) Connect(address string, remoteStaticKey []byte, remoteIdentHash data.Hash) (*Session, error) {
	// Resolve address
	remoteAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	// Determine which connection to use
	var conn *net.UDPConn
	if remoteAddr.IP.To4() != nil {
		conn = s.conn
	} else {
		conn = s.connV6
	}

	if conn == nil {
		return nil, ErrSessionTerminated
	}

	// Create session
	session, err := NewSession(&SessionConfig{
		Conn:           conn,
		RemoteAddr:     remoteAddr,
		LocalIdentity:  s.localIdentity,
		LocalStaticKey: s.localStaticKey,
		OnMessage:      s.createMessageHandler(),
		OnTerminate:    s.createTerminateHandler(0), // Will be set after connect
	})
	if err != nil {
		return nil, err
	}

	// Add to sessions
	s.mu.Lock()
	s.sessions[session.localConnID] = session
	s.mu.Unlock()

	// Connect
	if err := session.Connect(remoteStaticKey, remoteIdentHash); err != nil {
		s.mu.Lock()
		delete(s.sessions, session.localConnID)
		s.mu.Unlock()
		return nil, err
	}

	// Notify callback
	if s.onSession != nil {
		s.onSession(session)
	}

	return session, nil
}

// GetSession returns a session by connection ID.
func (s *Server) GetSession(connID uint64) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[connID]
}

// SessionCount returns the number of active sessions.
func (s *Server) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// Sessions returns a copy of all active sessions.
func (s *Server) Sessions() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// createMessageHandler creates a message handler for sessions.
func (s *Server) createMessageHandler() func(*i2np.RawMessage) {
	return func(msg *i2np.RawMessage) {
		// Forward to server callback if set
	}
}

// createTerminateHandler creates a termination handler for sessions.
func (s *Server) createTerminateHandler(connID uint64) func(TerminationReason) {
	return func(reason TerminationReason) {
		if connID != 0 {
			s.mu.Lock()
			delete(s.sessions, connID)
			s.mu.Unlock()
		}
	}
}

// maintenance performs periodic maintenance tasks.
func (s *Server) maintenance() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.cleanupSessions()
		}
	}
}

// cleanupSessions removes idle sessions.
func (s *Server) cleanupSessions() {
	now := time.Now()

	s.mu.RLock()
	var toTerminate []*Session
	for _, session := range s.sessions {
		if now.Sub(session.LastActivity()) > TerminationTimeout {
			toTerminate = append(toTerminate, session)
		}
	}
	s.mu.RUnlock()

	for _, session := range toTerminate {
		session.Terminate(TermIdleTimeout)
	}
}

// ListenAddr returns the IPv4 listen address.
func (s *Server) ListenAddr() string {
	if s.conn != nil {
		return s.conn.LocalAddr().String()
	}
	return ""
}

// ListenAddrV6 returns the IPv6 listen address.
func (s *Server) ListenAddrV6() string {
	if s.connV6 != nil {
		return s.connV6.LocalAddr().String()
	}
	return ""
}
