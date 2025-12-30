package ssu2

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

// Session represents an SSU2 session with a remote router.
type Session struct {
	mu sync.RWMutex

	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	state      SessionState

	localConnID     uint64
	remoteConnID    uint64
	localStaticKey  *crypto.X25519Keys
	localIdentity   []byte
	remoteIdentHash data.Hash
	remoteStaticKey [32]byte

	handshake *crypto.NoiseHandshake
	encoder   *PacketEncoder
	decoder   *PacketDecoder

	packetNumber     uint32
	receivedPackets  map[uint32]bool
	sentPackets      map[uint32]*SentPacket
	congestion       *CongestionState

	fragmentAssembler *FragmentAssembler

	sendQueue chan *i2np.RawMessage

	lastActivity    time.Time
	established     time.Time
	terminateReason TerminationReason

	onMessage   func(*i2np.RawMessage)
	onTerminate func(TerminationReason)

	done chan struct{}
}

// SentPacket tracks a sent packet for retransmission.
type SentPacket struct {
	Data     []byte
	SentTime time.Time
	Resends  int
}

// FragmentAssembler reassembles fragmented messages.
type FragmentAssembler struct {
	mu       sync.Mutex
	messages map[uint32]*IncompleteMessage
}

// IncompleteMessage represents a message being reassembled.
type IncompleteMessage struct {
	TotalSize  uint16
	Fragments  map[int][]byte
	LastUpdate time.Time
}

// NewFragmentAssembler creates a new fragment assembler.
func NewFragmentAssembler() *FragmentAssembler {
	return &FragmentAssembler{
		messages: make(map[uint32]*IncompleteMessage),
	}
}

// AddFragment adds a fragment to an incomplete message.
func (f *FragmentAssembler) AddFragment(msgID uint32, fragNum int, isFirst bool, isLast bool, totalSize uint16, fragment []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	msg, ok := f.messages[msgID]
	if !ok {
		msg = &IncompleteMessage{
			Fragments:  make(map[int][]byte),
			LastUpdate: time.Now(),
		}
		f.messages[msgID] = msg
	}

	if isFirst {
		msg.TotalSize = totalSize
	}

	msg.Fragments[fragNum] = fragment
	msg.LastUpdate = time.Now()

	// Check if complete
	if isLast {
		// Try to assemble
		var total []byte
		for i := 0; ; i++ {
			frag, ok := msg.Fragments[i]
			if !ok {
				return nil // Missing fragment
			}
			total = append(total, frag...)
			if i == fragNum {
				break
			}
		}
		delete(f.messages, msgID)
		return total
	}

	return nil
}

// Cleanup removes old incomplete messages.
func (f *FragmentAssembler) Cleanup(timeout time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	for id, msg := range f.messages {
		if now.Sub(msg.LastUpdate) > timeout {
			delete(f.messages, id)
		}
	}
}

// SessionConfig contains configuration for creating a session.
type SessionConfig struct {
	Conn           *net.UDPConn
	RemoteAddr     *net.UDPAddr
	LocalIdentity  []byte
	LocalStaticKey *crypto.X25519Keys
	OnMessage      func(*i2np.RawMessage)
	OnTerminate    func(TerminationReason)
}

// NewSession creates a new SSU2 session.
func NewSession(config *SessionConfig) (*Session, error) {
	// Generate random connection ID
	connIDBytes := make([]byte, 8)
	if _, err := rand.Read(connIDBytes); err != nil {
		return nil, err
	}
	localConnID := binary.BigEndian.Uint64(connIDBytes)

	handshake, err := crypto.NewNoiseHandshake(config.LocalStaticKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		conn:              config.Conn,
		remoteAddr:        config.RemoteAddr,
		state:             StateUnknown,
		localConnID:       localConnID,
		localStaticKey:    config.LocalStaticKey,
		localIdentity:     config.LocalIdentity,
		handshake:         handshake,
		receivedPackets:   make(map[uint32]bool),
		sentPackets:       make(map[uint32]*SentPacket),
		congestion:        NewCongestionState(),
		fragmentAssembler: NewFragmentAssembler(),
		sendQueue:         make(chan *i2np.RawMessage, 100),
		lastActivity:      time.Now(),
		onMessage:         config.OnMessage,
		onTerminate:       config.OnTerminate,
		done:              make(chan struct{}),
	}, nil
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

// LocalConnID returns the local connection ID.
func (s *Session) LocalConnID() uint64 {
	return s.localConnID
}

// RemoteConnID returns the remote connection ID.
func (s *Session) RemoteConnID() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.remoteConnID
}

// Connect initiates an outbound connection.
func (s *Session) Connect(remoteStaticKey []byte, remoteIdentHash data.Hash) error {
	s.mu.Lock()
	copy(s.remoteStaticKey[:], remoteStaticKey)
	s.remoteIdentHash = remoteIdentHash
	s.state = StateSessionRequestSent
	s.mu.Unlock()

	// Initialize as initiator
	s.handshake.InitiatorInit(remoteStaticKey, true) // SSU2 mode

	// Build SessionRequest
	err := s.sendSessionRequest()
	if err != nil {
		return err
	}

	// Wait for SessionCreated (handled in packet receive loop)
	return nil
}

// sendSessionRequest sends the SessionRequest message.
func (s *Session) sendSessionRequest() error {
	// Mix ephemeral key into hash
	ephemeralPub := s.handshake.LocalEphemeral.PublicKey()
	s.handshake.State.MixHash(ephemeralPub)

	// Perform DH: es = DH(e, rs)
	err := s.handshake.MixDH(s.handshake.LocalEphemeral, s.remoteStaticKey[:])
	if err != nil {
		return err
	}

	// Build options
	options := make([]byte, 16)
	options[0] = 2 // Version
	binary.BigEndian.PutUint32(options[4:8], uint32(time.Now().Unix()))

	// Encrypt options
	encrypted, err := s.handshake.State.Encrypt(options)
	if err != nil {
		return err
	}

	// Build packet: Header + X + encrypted options
	packet := make([]byte, LongHeaderSize+32+len(encrypted))

	// Header (obfuscated with ChaCha20)
	binary.BigEndian.PutUint64(packet[0:8], s.localConnID) // Source conn ID as dest for now
	binary.BigEndian.PutUint32(packet[8:12], 0)            // Packet number
	packet[12] = byte(MsgSessionRequest)
	packet[13] = 0 // Flags
	packet[14] = 2 // Version
	packet[15] = 2 // Net ID

	// Ephemeral key
	copy(packet[LongHeaderSize:LongHeaderSize+32], ephemeralPub)

	// Encrypted payload
	copy(packet[LongHeaderSize+32:], encrypted)

	// Send packet
	_, err = s.conn.WriteToUDP(packet, s.remoteAddr)
	return err
}

// ProcessPacket processes an incoming packet.
func (s *Session) ProcessPacket(data []byte) error {
	if len(data) < ShortHeaderSize {
		return ErrInvalidPacket
	}

	// Parse header
	header, err := ParseHeader(data)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()

	// Handle based on state and message type
	switch header.Type {
	case MsgSessionRequest:
		return s.handleSessionRequest(data)
	case MsgSessionCreated:
		return s.handleSessionCreated(data)
	case MsgSessionConfirmed:
		return s.handleSessionConfirmed(data)
	case MsgData:
		return s.handleData(data)
	case MsgRetry:
		return s.handleRetry(data)
	default:
		return ErrInvalidPacket
	}
}

// handleSessionRequest handles an incoming SessionRequest.
func (s *Session) handleSessionRequest(data []byte) error {
	s.mu.Lock()
	s.state = StateSessionRequestReceived
	s.mu.Unlock()

	// Initialize as responder
	s.handshake.ResponderInit(true) // SSU2 mode

	// Extract ephemeral key
	if len(data) < LongHeaderSize+32 {
		return ErrInvalidPacket
	}

	remoteEphemeral := data[LongHeaderSize : LongHeaderSize+32]
	s.handshake.RemoteEphemeral = make([]byte, 32)
	copy(s.handshake.RemoteEphemeral, remoteEphemeral)

	// Mix ephemeral into hash
	s.handshake.State.MixHash(remoteEphemeral)

	// Perform DH: es = DH(s, re)
	err := s.handshake.MixDH(s.localStaticKey, remoteEphemeral)
	if err != nil {
		return err
	}

	// Decrypt options
	encrypted := data[LongHeaderSize+32:]
	_, err = s.handshake.State.Decrypt(encrypted)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Send SessionCreated
	return s.sendSessionCreated()
}

// sendSessionCreated sends the SessionCreated message.
func (s *Session) sendSessionCreated() error {
	s.mu.Lock()
	s.state = StateSessionCreatedSent
	s.mu.Unlock()

	// Mix our ephemeral key
	ephemeralPub := s.handshake.LocalEphemeral.PublicKey()
	s.handshake.State.MixHash(ephemeralPub)

	// Perform DH: ee = DH(e, re)
	err := s.handshake.MixDH(s.handshake.LocalEphemeral, s.handshake.RemoteEphemeral)
	if err != nil {
		return err
	}

	// Build options
	options := make([]byte, 16)
	options[0] = 2 // Version
	binary.BigEndian.PutUint32(options[4:8], uint32(time.Now().Unix()))

	// Encrypt options
	encrypted, err := s.handshake.State.Encrypt(options)
	if err != nil {
		return err
	}

	// Build packet
	packet := make([]byte, LongHeaderSize+32+len(encrypted))

	binary.BigEndian.PutUint64(packet[0:8], s.remoteConnID)
	binary.BigEndian.PutUint32(packet[8:12], 0)
	packet[12] = byte(MsgSessionCreated)
	packet[14] = 2 // Version
	packet[15] = 2 // Net ID

	copy(packet[LongHeaderSize:LongHeaderSize+32], ephemeralPub)
	copy(packet[LongHeaderSize+32:], encrypted)

	_, err = s.conn.WriteToUDP(packet, s.remoteAddr)
	return err
}

// handleSessionCreated handles an incoming SessionCreated.
func (s *Session) handleSessionCreated(data []byte) error {
	if s.State() != StateSessionRequestSent {
		return ErrInvalidPacket
	}

	if len(data) < LongHeaderSize+32 {
		return ErrInvalidPacket
	}

	// Extract ephemeral key
	remoteEphemeral := data[LongHeaderSize : LongHeaderSize+32]
	s.handshake.RemoteEphemeral = make([]byte, 32)
	copy(s.handshake.RemoteEphemeral, remoteEphemeral)

	// Mix ephemeral
	s.handshake.State.MixHash(remoteEphemeral)

	// Perform DH: ee
	err := s.handshake.MixDH(s.handshake.LocalEphemeral, remoteEphemeral)
	if err != nil {
		return err
	}

	// Decrypt
	encrypted := data[LongHeaderSize+32:]
	_, err = s.handshake.State.Decrypt(encrypted)
	if err != nil {
		return ErrDecryptionFailed
	}

	s.mu.Lock()
	s.state = StateSessionCreatedReceived
	s.mu.Unlock()

	// Send SessionConfirmed
	return s.sendSessionConfirmed()
}

// sendSessionConfirmed sends the SessionConfirmed message.
func (s *Session) sendSessionConfirmed() error {
	// Perform DH: se = DH(s, re)
	err := s.handshake.MixDH(s.localStaticKey, s.handshake.RemoteEphemeral)
	if err != nil {
		return err
	}

	// Encrypt static key
	staticPub := s.localStaticKey.PublicKey()
	encryptedStatic, err := s.handshake.State.Encrypt(staticPub)
	if err != nil {
		return err
	}

	// Encrypt RouterInfo
	encryptedRI, err := s.handshake.State.Encrypt(s.localIdentity)
	if err != nil {
		return err
	}

	// Derive data phase keys
	s.deriveDataPhaseKeys()

	// Build packet
	packet := make([]byte, LongHeaderSize+len(encryptedStatic)+len(encryptedRI))

	binary.BigEndian.PutUint64(packet[0:8], s.remoteConnID)
	binary.BigEndian.PutUint32(packet[8:12], 0)
	packet[12] = byte(MsgSessionConfirmed)
	packet[14] = 2
	packet[15] = 2

	copy(packet[LongHeaderSize:], encryptedStatic)
	copy(packet[LongHeaderSize+len(encryptedStatic):], encryptedRI)

	_, err = s.conn.WriteToUDP(packet, s.remoteAddr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.state = StateEstablished
	s.established = time.Now()
	s.mu.Unlock()

	return nil
}

// handleSessionConfirmed handles an incoming SessionConfirmed.
func (s *Session) handleSessionConfirmed(data []byte) error {
	if s.State() != StateSessionCreatedSent {
		return ErrInvalidPacket
	}

	if len(data) < LongHeaderSize+48 {
		return ErrInvalidPacket
	}

	// Decrypt static key
	encryptedStatic := data[LongHeaderSize : LongHeaderSize+48]
	staticKey, err := s.handshake.State.Decrypt(encryptedStatic)
	if err != nil {
		return ErrDecryptionFailed
	}

	copy(s.remoteStaticKey[:], staticKey)

	// Perform DH: se = DH(e, rs)
	err = s.handshake.MixDH(s.handshake.LocalEphemeral, s.remoteStaticKey[:])
	if err != nil {
		return err
	}

	// Decrypt RouterInfo (rest of packet)
	encryptedRI := data[LongHeaderSize+48:]
	_, err = s.handshake.State.Decrypt(encryptedRI)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Derive data phase keys
	s.deriveDataPhaseKeys()

	s.mu.Lock()
	s.state = StateEstablished
	s.established = time.Now()
	s.mu.Unlock()

	return nil
}

// handleData handles a data packet.
func (s *Session) handleData(data []byte) error {
	if s.State() != StateEstablished {
		return ErrInvalidPacket
	}

	// Decrypt packet
	header, blocks, err := s.decoder.DecodePacket(data)
	if err != nil {
		return err
	}

	// Track received packet
	s.mu.Lock()
	s.receivedPackets[header.PacketNumber] = true
	s.mu.Unlock()

	// Process blocks
	for _, block := range blocks {
		switch block.Type {
		case BlockI2NPMessage:
			msg, err := i2np.ParseFromNTCP2(block.Data) // Same format as NTCP2
			if err == nil && s.onMessage != nil {
				s.onMessage(msg)
			}

		case BlockFirstFragment:
			msgID, totalSize, fragment, err := ParseFirstFragmentBlock(block.Data)
			if err == nil {
				if complete := s.fragmentAssembler.AddFragment(msgID, 0, true, false, totalSize, fragment); complete != nil {
					msg, err := i2np.ParseFromNTCP2(complete)
					if err == nil && s.onMessage != nil {
						s.onMessage(msg)
					}
				}
			}

		case BlockFollowOnFragment:
			msgID, fragNum, isLast, fragment, err := ParseFollowOnFragmentBlock(block.Data)
			if err == nil {
				if complete := s.fragmentAssembler.AddFragment(msgID, int(fragNum), false, isLast, 0, fragment); complete != nil {
					msg, err := i2np.ParseFromNTCP2(complete)
					if err == nil && s.onMessage != nil {
						s.onMessage(msg)
					}
				}
			}

		case BlockACK:
			s.handleACK(block.Data)

		case BlockTermination:
			if len(block.Data) >= 9 {
				reason := TerminationReason(block.Data[8])
				s.terminate(reason)
			}
		}
	}

	return nil
}

// handleACK processes an ACK block.
func (s *Session) handleACK(data []byte) {
	ackThrough, ranges, err := ParseACKBlock(data)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Mark packets as acknowledged
	for pn := range s.sentPackets {
		if pn <= ackThrough {
			// Check ranges for NACKs
			acked := true
			offset := ackThrough
			for _, r := range ranges {
				offset -= r[0] // Ack count
				if pn > offset {
					break
				}
				offset -= r[1] // Nack count
				if pn > offset {
					acked = false
					break
				}
			}

			if acked {
				sent := s.sentPackets[pn]
				if sent != nil {
					rtt := time.Since(sent.SentTime)
					s.congestion.UpdateRTT(rtt)
					s.congestion.OnPacketAcked()
				}
				delete(s.sentPackets, pn)
			}
		}
	}
}

// handleRetry handles a Retry message.
func (s *Session) handleRetry(data []byte) error {
	// Retry contains a token we should use in next SessionRequest
	// For now, just note that we need to retry
	return nil
}

// deriveDataPhaseKeys derives the keys for the data phase.
func (s *Session) deriveDataPhaseKeys() {
	ck := s.handshake.State.GetCK()

	// Derive keys using HKDF
	keyMaterial, _ := crypto.HKDF(nil, ck, []byte("SSU2"), 96)

	// Split into keys
	sendKey := keyMaterial[:32]
	recvKey := keyMaterial[32:64]
	headerKey := keyMaterial[64:96]

	s.encoder = NewPacketEncoder(sendKey, headerKey, s.localConnID)
	s.decoder = NewPacketDecoder(recvKey, headerKey, s.localConnID)
}

// SendMessage sends an I2NP message through the session.
func (s *Session) SendMessage(msg *i2np.RawMessage) error {
	if s.State() != StateEstablished {
		return ErrSessionTerminated
	}

	select {
	case s.sendQueue <- msg:
		return nil
	default:
		return ErrPacketTooLarge // Queue full
	}
}

// Terminate initiates session termination.
func (s *Session) Terminate(reason TerminationReason) {
	s.terminate(reason)
}

// terminate terminates the session.
func (s *Session) terminate(reason TerminationReason) {
	s.mu.Lock()
	if s.state == StateTerminated {
		s.mu.Unlock()
		return
	}
	s.state = StateTerminated
	s.terminateReason = reason
	s.mu.Unlock()

	// Send termination block
	if s.encoder != nil {
		block := TerminationBlock(reason)
		packet, _ := s.encoder.EncodePacket(s.remoteConnID, MsgData, []Block{block})
		s.conn.WriteToUDP(packet, s.remoteAddr)
	}

	close(s.done)

	if s.onTerminate != nil {
		s.onTerminate(reason)
	}
}

// LastActivity returns the time of last activity.
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// Close closes the session gracefully.
func (s *Session) Close() error {
	s.Terminate(TermNormalClose)
	return nil
}
