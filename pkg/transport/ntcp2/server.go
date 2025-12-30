package ntcp2

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/debug"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

var log = debug.NewLogger(debug.SubNTCP2)

// Server manages NTCP2 connections.
type Server struct {
	mu sync.RWMutex

	listener    net.Listener
	listenerV6  net.Listener
	localAddr   string
	localAddrV6 string

	localIdentity  []byte
	localStaticKey *crypto.X25519Keys

	sessions     map[data.Hash]*Session
	pendingConns map[string]*Session // Address -> pending inbound session

	running bool
	done    chan struct{}

	onSession func(*Session)
	onMessage func(*Session, *i2np.RawMessage)
}

// ServerConfig contains configuration for the NTCP2 server.
type ServerConfig struct {
	ListenAddr     string // IPv4 address:port
	ListenAddrV6   string // IPv6 address:port
	LocalIdentity  []byte
	LocalStaticKey *crypto.X25519Keys
	OnSession      func(*Session)
	OnMessage      func(*Session, *i2np.RawMessage)
}

// NewServer creates a new NTCP2 server.
func NewServer(config *ServerConfig) *Server {
	return &Server{
		localAddr:      config.ListenAddr,
		localAddrV6:    config.ListenAddrV6,
		localIdentity:  config.LocalIdentity,
		localStaticKey: config.LocalStaticKey,
		sessions:       make(map[data.Hash]*Session),
		pendingConns:   make(map[string]*Session),
		done:           make(chan struct{}),
		onSession:      config.OnSession,
		onMessage:      config.OnMessage,
	}
}

// Start starts the NTCP2 server.
func (s *Server) Start() error {
	defer log.FuncEntry()()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		log.Debug("server already running")
		return nil
	}

	// Start IPv4 listener
	if s.localAddr != "" {
		log.Info("starting IPv4 listener on %s", s.localAddr)
		listener, err := net.Listen("tcp", s.localAddr)
		if err != nil {
			log.Error("failed to start IPv4 listener: %v", err)
			return err
		}
		s.listener = listener
		go s.acceptLoop(listener)
	}

	// Start IPv6 listener
	if s.localAddrV6 != "" {
		log.Info("starting IPv6 listener on %s", s.localAddrV6)
		listener, err := net.Listen("tcp6", s.localAddrV6)
		if err != nil {
			log.Error("failed to start IPv6 listener: %v", err)
			if s.listener != nil {
				s.listener.Close()
			}
			return err
		}
		s.listenerV6 = listener
		go s.acceptLoop(listener)
	}

	s.running = true
	log.Info("NTCP2 server started")

	// Start termination checker
	go s.terminationChecker()

	return nil
}

// Stop stops the NTCP2 server.
func (s *Server) Stop() {
	defer log.FuncEntry()()

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		log.Debug("server not running")
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	// Close listeners
	if s.listener != nil {
		s.listener.Close()
	}
	if s.listenerV6 != nil {
		s.listenerV6.Close()
	}

	// Terminate all sessions
	s.mu.RLock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.RUnlock()

	log.Info("terminating %d sessions", len(sessions))
	for _, session := range sessions {
		session.Terminate(TermRouterShutdown)
	}
	log.Info("NTCP2 server stopped")
}

// acceptLoop accepts incoming connections.
func (s *Server) acceptLoop(listener net.Listener) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		go s.handleInbound(conn)
	}
}

// handleInbound handles an incoming connection.
func (s *Server) handleInbound(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Debug("inbound connection from %s", remoteAddr)

	// Check for pending connection from same address
	s.mu.Lock()
	if _, exists := s.pendingConns[remoteAddr]; exists {
		s.mu.Unlock()
		log.Warn("duplicate pending connection from %s, rejecting", remoteAddr)
		conn.Close()
		return
	}
	s.mu.Unlock()

	// Create session
	session := NewSession(conn, &SessionConfig{
		LocalIdentity:  s.localIdentity,
		LocalStaticKey: s.localStaticKey,
		OnMessage:      s.createMessageHandler(),
		OnTerminate:    s.createTerminateHandler(nil),
	}, true)

	// Track pending connection
	s.mu.Lock()
	s.pendingConns[remoteAddr] = session
	s.mu.Unlock()

	// Perform handshake
	log.Trace("performing inbound handshake with %s", remoteAddr)
	if err := session.Accept(); err != nil {
		log.Error("inbound handshake failed with %s: %v", remoteAddr, err)
		s.mu.Lock()
		delete(s.pendingConns, remoteAddr)
		s.mu.Unlock()
		conn.Close()
		return
	}

	// Move to established sessions
	s.mu.Lock()
	delete(s.pendingConns, remoteAddr)
	identHash := session.RemoteIdentHash()
	s.sessions[identHash] = session
	session.onTerminate = s.createTerminateHandler(&identHash)
	s.mu.Unlock()

	log.Info("session established with %s (hash: %x...)", remoteAddr, identHash[:8])

	// Notify callback
	if s.onSession != nil {
		s.onSession(session)
	}
}

// Connect initiates an outbound connection.
func (s *Server) Connect(address string, remoteStaticKey []byte, remoteIdentHash data.Hash) (*Session, error) {
	log.Debug("connecting to %s (hash: %x...)", address, remoteIdentHash[:8])

	// Check if we already have a session
	s.mu.RLock()
	if existing, ok := s.sessions[remoteIdentHash]; ok {
		s.mu.RUnlock()
		log.Trace("reusing existing session for %x...", remoteIdentHash[:8])
		return existing, nil
	}
	s.mu.RUnlock()

	// Dial with timeout
	log.Trace("dialing %s with timeout %v", address, ConnectTimeout)
	conn, err := net.DialTimeout("tcp", address, ConnectTimeout)
	if err != nil {
		log.Error("dial failed to %s: %v", address, err)
		return nil, err
	}

	// Create session
	session := NewSession(conn, &SessionConfig{
		LocalIdentity:  s.localIdentity,
		LocalStaticKey: s.localStaticKey,
		OnMessage:      s.createMessageHandler(),
		OnTerminate:    s.createTerminateHandler(&remoteIdentHash),
	}, false)

	// Perform handshake
	log.Trace("performing outbound handshake with %s", address)
	if err := session.Connect(remoteStaticKey, remoteIdentHash); err != nil {
		log.Error("outbound handshake failed with %s: %v", address, err)
		conn.Close()
		return nil, err
	}

	// Add to sessions
	s.mu.Lock()
	s.sessions[remoteIdentHash] = session
	s.mu.Unlock()

	log.Info("outbound session established to %s (hash: %x...)", address, remoteIdentHash[:8])

	// Notify callback
	if s.onSession != nil {
		s.onSession(session)
	}

	return session, nil
}

// GetSession returns an existing session by identity hash.
func (s *Server) GetSession(identHash data.Hash) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[identHash]
}

// SendMessage sends a message to a specific peer.
func (s *Server) SendMessage(identHash data.Hash, msg *i2np.RawMessage) error {
	session := s.GetSession(identHash)
	if session == nil {
		return ErrConnectionClosed
	}
	return session.SendMessage(msg)
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
		// Find the session and call the server callback
		// This is a simplified version; in practice we'd need the session reference
	}
}

// createTerminateHandler creates a termination handler for sessions.
func (s *Server) createTerminateHandler(identHash *data.Hash) func(TerminationReason) {
	return func(reason TerminationReason) {
		if identHash != nil {
			s.mu.Lock()
			delete(s.sessions, *identHash)
			s.mu.Unlock()
		}
	}
}

// terminationChecker periodically checks for idle sessions.
func (s *Server) terminationChecker() {
	ticker := time.NewTicker(TerminationCheckTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.checkIdleSessions()
		}
	}
}

// checkIdleSessions terminates sessions that have been idle too long.
func (s *Server) checkIdleSessions() {
	now := time.Now()
	timeout := TerminationTimeout

	s.mu.RLock()
	var toTerminate []*Session
	for _, session := range s.sessions {
		if now.Sub(session.LastActivity()) > timeout {
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
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// ListenAddrV6 returns the IPv6 listen address.
func (s *Server) ListenAddrV6() string {
	if s.listenerV6 != nil {
		return s.listenerV6.Addr().String()
	}
	return ""
}
