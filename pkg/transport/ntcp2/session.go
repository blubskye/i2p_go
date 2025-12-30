package ntcp2

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

// SessionState represents the state of an NTCP2 session.
type SessionState int

const (
	StateNew SessionState = iota
	StateHandshaking
	StateEstablished
	StateTerminating
	StateTerminated
)

// Session represents an NTCP2 session with a remote router.
type Session struct {
	mu sync.RWMutex

	conn     net.Conn
	state    SessionState
	isInbound bool

	localIdentity   []byte
	localStaticKey  *crypto.X25519Keys
	remoteIdentHash data.Hash
	remoteStaticKey [32]byte

	encoder *FrameEncoder
	decoder *FrameDecoder

	sendSequence    uint64
	receiveSequence uint64

	sendQueue chan []byte
	recvQueue chan *i2np.RawMessage

	lastActivity    time.Time
	established     time.Time
	terminateReason TerminationReason

	onMessage   func(*i2np.RawMessage)
	onTerminate func(TerminationReason)

	done chan struct{}
}

// SessionConfig contains configuration for creating a session.
type SessionConfig struct {
	LocalIdentity  []byte
	LocalStaticKey *crypto.X25519Keys
	OnMessage      func(*i2np.RawMessage)
	OnTerminate    func(TerminationReason)
}

// NewSession creates a new NTCP2 session.
func NewSession(conn net.Conn, config *SessionConfig, isInbound bool) *Session {
	return &Session{
		conn:           conn,
		state:          StateNew,
		isInbound:      isInbound,
		localIdentity:  config.LocalIdentity,
		localStaticKey: config.LocalStaticKey,
		sendQueue:      make(chan []byte, MaxOutgoingQueueSize),
		recvQueue:      make(chan *i2np.RawMessage, 100),
		lastActivity:   time.Now(),
		onMessage:      config.OnMessage,
		onTerminate:    config.OnTerminate,
		done:           make(chan struct{}),
	}
}

// State returns the current session state.
func (s *Session) State() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// IsEstablished returns true if the session is established.
func (s *Session) IsEstablished() bool {
	return s.State() == StateEstablished
}

// RemoteIdentHash returns the remote router's identity hash.
func (s *Session) RemoteIdentHash() data.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.remoteIdentHash
}

// Connect initiates an outbound connection (Alice role).
func (s *Session) Connect(remoteStaticKey []byte, remoteIdentHash data.Hash) error {
	s.mu.Lock()
	copy(s.remoteStaticKey[:], remoteStaticKey)
	s.remoteIdentHash = remoteIdentHash
	s.state = StateHandshaking
	s.mu.Unlock()

	// Set connection deadline for handshake
	s.conn.SetDeadline(time.Now().Add(EstablishTimeout))

	// Create handshaker
	handshaker, err := NewHandshaker(s.localStaticKey, s.localIdentity, true)
	if err != nil {
		return err
	}
	handshaker.SetRemoteStaticKey(remoteStaticKey)

	// Send SessionRequest
	sessionRequest, err := handshaker.CreateSessionRequest(16)
	if err != nil {
		return err
	}

	if _, err := s.conn.Write(sessionRequest); err != nil {
		return err
	}

	// Receive SessionCreated
	sessionCreated := make([]byte, SessionCreatedMaxSize)
	n, err := s.conn.Read(sessionCreated)
	if err != nil {
		return err
	}

	paddingLen, err := handshaker.ProcessSessionCreated(sessionCreated[:n])
	if err != nil {
		return err
	}
	_ = paddingLen

	// Send SessionConfirmed
	sessionConfirmed, err := handshaker.CreateSessionConfirmed()
	if err != nil {
		return err
	}

	if _, err := s.conn.Write(sessionConfirmed); err != nil {
		return err
	}

	// Set up data phase encryption
	s.encoder = NewFrameEncoder(handshaker.SendKey, handshaker.SendSipKey)
	s.decoder = NewFrameDecoder(handshaker.ReceiveKey, handshaker.ReceiveSipKey)

	// Clear deadline and mark established
	s.conn.SetDeadline(time.Time{})
	s.mu.Lock()
	s.state = StateEstablished
	s.established = time.Now()
	s.mu.Unlock()

	// Start data phase
	go s.readLoop()
	go s.writeLoop()

	return nil
}

// Accept accepts an inbound connection (Bob role).
func (s *Session) Accept() error {
	s.mu.Lock()
	s.state = StateHandshaking
	s.mu.Unlock()

	// Set connection deadline for handshake
	s.conn.SetDeadline(time.Now().Add(EstablishTimeout))

	// Create handshaker
	handshaker, err := NewHandshaker(s.localStaticKey, s.localIdentity, false)
	if err != nil {
		return err
	}

	// Receive SessionRequest
	sessionRequest := make([]byte, SessionRequestMaxSize)
	n, err := s.conn.Read(sessionRequest)
	if err != nil {
		return err
	}

	paddingLen, clockSkew, err := handshaker.ProcessSessionRequest(sessionRequest[:n])
	if err != nil {
		return err
	}
	_ = paddingLen

	if clockSkew {
		return ErrClockSkew
	}

	// Send SessionCreated
	sessionCreated, err := handshaker.CreateSessionCreated(16)
	if err != nil {
		return err
	}

	if _, err := s.conn.Write(sessionCreated); err != nil {
		return err
	}

	// Receive SessionConfirmed
	sessionConfirmed := make([]byte, 4096) // Variable size
	n, err = s.conn.Read(sessionConfirmed)
	if err != nil {
		return err
	}

	if err := handshaker.ProcessSessionConfirmed(sessionConfirmed[:n]); err != nil {
		return err
	}

	// Store remote identity
	copy(s.remoteStaticKey[:], handshaker.remoteStaticKey[:])

	// Set up data phase encryption
	s.encoder = NewFrameEncoder(handshaker.SendKey, handshaker.SendSipKey)
	s.decoder = NewFrameDecoder(handshaker.ReceiveKey, handshaker.ReceiveSipKey)

	// Clear deadline and mark established
	s.conn.SetDeadline(time.Time{})
	s.mu.Lock()
	s.state = StateEstablished
	s.established = time.Now()
	s.mu.Unlock()

	// Start data phase
	go s.readLoop()
	go s.writeLoop()

	return nil
}

// SendMessage sends an I2NP message through the session.
func (s *Session) SendMessage(msg *i2np.RawMessage) error {
	if s.State() != StateEstablished {
		return ErrSessionTerminated
	}

	// Serialize message with NTCP2 header
	msgBytes := msg.ToNTCP2Bytes()

	select {
	case s.sendQueue <- msgBytes:
		return nil
	default:
		return ErrFrameTooLarge // Queue full
	}
}

// SendRouterInfo sends our RouterInfo to the peer.
func (s *Session) SendRouterInfo(routerInfo []byte, flood bool) error {
	if s.State() != StateEstablished {
		return ErrSessionTerminated
	}

	block := RouterInfoBlock(routerInfo, flood)
	frame := NewFrame(block)
	payload := frame.ToBytes()

	select {
	case s.sendQueue <- payload:
		return nil
	default:
		return ErrFrameTooLarge
	}
}

// Terminate initiates session termination.
func (s *Session) Terminate(reason TerminationReason) {
	s.mu.Lock()
	if s.state == StateTerminating || s.state == StateTerminated {
		s.mu.Unlock()
		return
	}
	s.state = StateTerminating
	s.terminateReason = reason
	s.mu.Unlock()

	// Send termination block
	block := TerminationBlock(reason, s.sendSequence)
	frame := NewFrame(block)
	payload := frame.ToBytes()

	// Try to send, but don't block
	select {
	case s.sendQueue <- payload:
	default:
	}

	// Close the connection after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.close()
	}()
}

// close closes the session.
func (s *Session) close() {
	s.mu.Lock()
	if s.state == StateTerminated {
		s.mu.Unlock()
		return
	}
	s.state = StateTerminated
	s.mu.Unlock()

	close(s.done)
	s.conn.Close()

	if s.onTerminate != nil {
		s.onTerminate(s.terminateReason)
	}
}

// readLoop reads and processes incoming frames.
func (s *Session) readLoop() {
	defer s.close()

	lenBuf := make([]byte, 2)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		// Set read deadline
		s.conn.SetReadDeadline(time.Now().Add(TerminationTimeout))

		// Read encrypted length
		if _, err := io.ReadFull(s.conn, lenBuf); err != nil {
			return
		}

		// Decode length
		frameLen := s.decoder.DecodeLength(lenBuf)
		if frameLen > uint16(UnencryptedFrameMaxSize+FrameMACSize) {
			s.Terminate(TermAEADFramingError)
			return
		}

		// Read frame body
		frameBuf := make([]byte, frameLen)
		if _, err := io.ReadFull(s.conn, frameBuf); err != nil {
			return
		}

		// Decrypt frame
		payload, err := s.decoder.DecodeFrame(frameBuf)
		if err != nil {
			s.Terminate(TermDataPhaseAEADFailure)
			return
		}

		// Parse blocks
		blocks, err := ParseBlocks(payload)
		if err != nil {
			s.Terminate(TermPayloadFormatError)
			return
		}

		// Process blocks
		s.processBlocks(blocks)

		s.mu.Lock()
		s.lastActivity = time.Now()
		s.receiveSequence++
		s.mu.Unlock()
	}
}

// writeLoop sends outgoing frames.
func (s *Session) writeLoop() {
	// Buffer for accumulating messages
	var pendingMessages [][]byte
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case msg := <-s.sendQueue:
			pendingMessages = append(pendingMessages, msg)
			// Check if we should send immediately
			if len(pendingMessages) >= 10 || s.totalSize(pendingMessages) >= SendAfterFrameSize {
				s.sendFrame(pendingMessages)
				pendingMessages = nil
			}
		case <-ticker.C:
			if len(pendingMessages) > 0 {
				s.sendFrame(pendingMessages)
				pendingMessages = nil
			}
		}
	}
}

// totalSize returns the total size of pending messages.
func (s *Session) totalSize(messages [][]byte) int {
	var size int
	for _, m := range messages {
		size += len(m)
	}
	return size
}

// sendFrame encodes and sends a frame with the given blocks.
func (s *Session) sendFrame(messages [][]byte) {
	// Build frame with I2NP message blocks
	var blocks []Block
	for _, msg := range messages {
		blocks = append(blocks, I2NPMessageBlock(msg))
	}

	// Add padding
	paddingSize := calculatePadding(s.totalSize(messages))
	if paddingSize > 0 {
		blocks = append(blocks, PaddingBlock(paddingSize))
	}

	frame := &Frame{Blocks: blocks}
	payload := frame.ToBytes()

	// Encrypt and send
	encrypted, err := s.encoder.EncodeFrame(payload)
	if err != nil {
		return
	}

	s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	s.conn.Write(encrypted)

	s.mu.Lock()
	s.sendSequence++
	s.mu.Unlock()
}

// processBlocks processes received blocks.
func (s *Session) processBlocks(blocks []Block) {
	for _, block := range blocks {
		switch block.Type {
		case BlockDateTime:
			// Check clock skew
			ts, err := ParseDateTimeBlock(block.Data)
			if err != nil {
				continue
			}
			now := uint32(time.Now().Unix())
			diff := int64(now) - int64(ts)
			if diff < 0 {
				diff = -diff
			}
			if diff > int64(ClockSkew.Seconds()) {
				s.Terminate(TermClockSkew)
				return
			}

		case BlockOptions:
			// Process options (currently ignored)

		case BlockRouterInfo:
			// Process RouterInfo update
			routerInfo, _, err := ParseRouterInfoBlock(block.Data)
			if err != nil {
				continue
			}
			_ = routerInfo // TODO: Process RouterInfo update

		case BlockI2NPMessage:
			// Parse I2NP message
			raw, err := i2np.ParseFromNTCP2(block.Data)
			if err != nil {
				continue
			}
			if s.onMessage != nil {
				s.onMessage(raw)
			}

		case BlockTermination:
			reason, _, err := ParseTerminationBlock(block.Data)
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.terminateReason = reason
			s.mu.Unlock()
			s.close()
			return

		case BlockPadding:
			// Ignore padding
		}
	}
}

// calculatePadding calculates appropriate padding size.
func calculatePadding(payloadSize int) int {
	// Add padding to align to 16 bytes and add randomness
	minPadding := 16 - (payloadSize % 16)
	if minPadding == 16 {
		minPadding = 0
	}

	// Add random padding (0-15 bytes extra)
	buf := make([]byte, 1)
	binary.Read(nil, binary.BigEndian, buf)
	extraPadding := int(buf[0] & 0x0F)

	return minPadding + extraPadding
}

// LastActivity returns the time of the last activity.
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// Established returns the time when the session was established.
func (s *Session) Established() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.established
}

// Close closes the session gracefully.
func (s *Session) Close() error {
	s.Terminate(TermNormalClose)
	return nil
}
