package garlic

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

// Handler manages garlic sessions and message processing.
type Handler struct {
	mu sync.RWMutex

	localIdentity   data.Hash
	encryptionKey   []byte        // Our encryption private key
	encryptionType  uint16        // Our preferred encryption type

	// Sessions by destination
	sessions        map[data.Hash]Session

	// Tag to session mapping for incoming
	tagToSession    map[SessionTag]Session

	// Pending deliveries
	onDeliverLocal  func(*i2np.RawMessage)
	onDeliverRouter func(data.Hash, *i2np.RawMessage)
	onDeliverTunnel func(uint32, data.Hash, *i2np.RawMessage)

	running bool
	done    chan struct{}
}

// NewHandler creates a new garlic handler.
func NewHandler(localIdentity data.Hash, encKey []byte, encType uint16) *Handler {
	return &Handler{
		localIdentity:  localIdentity,
		encryptionKey:  encKey,
		encryptionType: encType,
		sessions:       make(map[data.Hash]Session),
		tagToSession:   make(map[SessionTag]Session),
		done:           make(chan struct{}),
	}
}

// SetDeliveryCallbacks sets the delivery callbacks.
func (h *Handler) SetDeliveryCallbacks(
	onLocal func(*i2np.RawMessage),
	onRouter func(data.Hash, *i2np.RawMessage),
	onTunnel func(uint32, data.Hash, *i2np.RawMessage),
) {
	h.onDeliverLocal = onLocal
	h.onDeliverRouter = onRouter
	h.onDeliverTunnel = onTunnel
}

// Start starts the handler.
func (h *Handler) Start() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.mu.Unlock()

	go h.maintenance()
}

// Stop stops the handler.
func (h *Handler) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	close(h.done)
	h.mu.Unlock()
}

// GetOrCreateSession gets or creates a session for a destination.
func (h *Handler) GetOrCreateSession(dest data.Hash, encKey []byte, encType uint16) (Session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check for existing session
	if session, ok := h.sessions[dest]; ok && !session.IsExpired() {
		return session, nil
	}

	// Create new session based on encryption type
	var session Session
	var err error

	switch encType {
	case EncryptionTypeECIES:
		var remoteKey [32]byte
		copy(remoteKey[:], encKey[:32])
		session, err = NewRatchetSession(dest, remoteKey)
		if err != nil {
			return nil, err
		}
	default:
		// Default to ElGamal
		session = NewElGamalSession(dest, encKey)
	}

	h.sessions[dest] = session
	return session, nil
}

// CreateGarlicMessage creates a garlic message with the given cloves.
func (h *Handler) CreateGarlicMessage(dest data.Hash, cloves []*Clove, encKey []byte, encType uint16) (*GarlicMessage, []byte, error) {
	// Get or create session
	session, err := h.GetOrCreateSession(dest, encKey, encType)
	if err != nil {
		return nil, nil, err
	}

	// Build garlic message
	msg := &GarlicMessage{
		Cloves:      cloves,
		Certificate: 0,
		MsgID:       generateMsgID(),
		Expiration:  time.Now().Add(60 * time.Second),
	}

	// Serialize the message
	plaintext := h.serializeGarlicMessage(msg)

	// Encrypt
	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return nil, nil, err
	}

	return msg, ciphertext, nil
}

// HandleGarlicMessage handles an incoming garlic message.
func (h *Handler) HandleGarlicMessage(data []byte) error {
	// Try to find the session using the session tag
	if len(data) < SessionTagSize {
		return ErrInvalidPayload
	}

	var tag SessionTag
	copy(tag[:], data[:SessionTagSize])

	h.mu.RLock()
	session := h.tagToSession[tag]
	h.mu.RUnlock()

	var plaintext []byte
	var err error

	if session != nil {
		// Decrypt with existing session
		plaintext, err = session.Decrypt(data)
		if err != nil {
			return err
		}
	} else {
		// Try to decrypt with our private key (first message)
		plaintext, err = h.decryptFirstMessage(data)
		if err != nil {
			return err
		}
	}

	// Parse garlic message
	msg, err := h.parseGarlicMessage(plaintext)
	if err != nil {
		return err
	}

	// Process cloves
	for _, clove := range msg.Cloves {
		if err := h.deliverClove(clove); err != nil {
			// Log error but continue with other cloves
		}
	}

	return nil
}

// decryptFirstMessage decrypts an initial message using our private key.
func (h *Handler) decryptFirstMessage(data []byte) ([]byte, error) {
	// This would use ElGamal or ECIES decryption depending on format
	// For now, return an error - requires full implementation
	return nil, ErrDecryptionFailed
}

// serializeGarlicMessage serializes a garlic message.
func (h *Handler) serializeGarlicMessage(msg *GarlicMessage) []byte {
	// Calculate size
	size := 1 + 4 + 8 // Certificate + MsgID + Expiration
	size += 1         // Clove count

	for _, clove := range msg.Cloves {
		size += h.cloveSize(clove)
	}

	buf := make([]byte, size)
	offset := 0

	// Certificate
	buf[offset] = msg.Certificate
	offset++

	// Message ID
	binary.BigEndian.PutUint32(buf[offset:], msg.MsgID)
	offset += 4

	// Expiration
	binary.BigEndian.PutUint64(buf[offset:], uint64(msg.Expiration.UnixMilli()))
	offset += 8

	// Clove count
	buf[offset] = byte(len(msg.Cloves))
	offset++

	// Serialize each clove
	for _, clove := range msg.Cloves {
		offset += h.serializeClove(buf[offset:], clove)
	}

	return buf[:offset]
}

// cloveSize returns the serialized size of a clove.
func (h *Handler) cloveSize(clove *Clove) int {
	size := 1 // Delivery instructions flag

	switch clove.DeliveryType {
	case DeliveryLocal:
		// No additional data
	case DeliveryDestination:
		size += 32 // Destination hash
	case DeliveryRouter:
		size += 32 // Router hash
	case DeliveryTunnel:
		size += 4 + 32 // Tunnel ID + Gateway hash
	}

	size += 4 + len(clove.Payload) // Length + payload
	return size
}

// serializeClove serializes a clove into a buffer.
func (h *Handler) serializeClove(buf []byte, clove *Clove) int {
	offset := 0

	// Delivery instructions
	flag := byte(clove.DeliveryType) << 4
	buf[offset] = flag
	offset++

	switch clove.DeliveryType {
	case DeliveryDestination:
		copy(buf[offset:], clove.ToHash[:])
		offset += 32
	case DeliveryRouter:
		copy(buf[offset:], clove.ToHash[:])
		offset += 32
	case DeliveryTunnel:
		binary.BigEndian.PutUint32(buf[offset:], clove.TunnelID)
		offset += 4
		copy(buf[offset:], clove.ToHash[:])
		offset += 32
	}

	// Payload length and data
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(clove.Payload)))
	offset += 4
	copy(buf[offset:], clove.Payload)
	offset += len(clove.Payload)

	return offset
}

// parseGarlicMessage parses a decrypted garlic message.
func (h *Handler) parseGarlicMessage(data []byte) (*GarlicMessage, error) {
	if len(data) < 14 { // Minimum size
		return nil, ErrInvalidPayload
	}

	msg := &GarlicMessage{}
	offset := 0

	// Certificate
	msg.Certificate = data[offset]
	offset++

	// Message ID
	msg.MsgID = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Expiration
	expMs := binary.BigEndian.Uint64(data[offset:])
	msg.Expiration = time.UnixMilli(int64(expMs))
	offset += 8

	// Clove count
	cloveCount := int(data[offset])
	offset++

	// Parse cloves
	msg.Cloves = make([]*Clove, 0, cloveCount)
	for i := 0; i < cloveCount && offset < len(data); i++ {
		clove, consumed, err := h.parseClove(data[offset:])
		if err != nil {
			return nil, err
		}
		msg.Cloves = append(msg.Cloves, clove)
		offset += consumed
	}

	return msg, nil
}

// parseClove parses a clove from data.
func (h *Handler) parseClove(data []byte) (*Clove, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrInvalidClove
	}

	clove := &Clove{}
	offset := 0

	// Delivery instructions
	flag := data[offset]
	clove.DeliveryType = DeliveryType((flag >> 4) & 0x0F)
	offset++

	switch clove.DeliveryType {
	case DeliveryLocal:
		// No additional data
	case DeliveryDestination:
		if len(data) < offset+32 {
			return nil, 0, ErrInvalidClove
		}
		copy(clove.ToHash[:], data[offset:offset+32])
		offset += 32
	case DeliveryRouter:
		if len(data) < offset+32 {
			return nil, 0, ErrInvalidClove
		}
		copy(clove.ToHash[:], data[offset:offset+32])
		offset += 32
	case DeliveryTunnel:
		if len(data) < offset+36 {
			return nil, 0, ErrInvalidClove
		}
		clove.TunnelID = binary.BigEndian.Uint32(data[offset:])
		offset += 4
		copy(clove.ToHash[:], data[offset:offset+32])
		offset += 32
	}

	// Payload
	if len(data) < offset+4 {
		return nil, 0, ErrInvalidClove
	}
	payloadLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(payloadLen) {
		return nil, 0, ErrInvalidClove
	}
	clove.Payload = make([]byte, payloadLen)
	copy(clove.Payload, data[offset:offset+int(payloadLen)])
	offset += int(payloadLen)

	return clove, offset, nil
}

// deliverClove delivers a clove to its destination.
func (h *Handler) deliverClove(clove *Clove) error {
	// Parse the payload as a raw I2NP message
	msg, err := i2np.ParseRawMessage(clove.Payload)
	if err != nil {
		// If parsing fails, wrap the payload as a simple message
		msg = i2np.NewRawMessage(i2np.TypeGarlic, clove.Payload)
	}

	switch clove.DeliveryType {
	case DeliveryLocal:
		if h.onDeliverLocal != nil {
			h.onDeliverLocal(msg)
		}
	case DeliveryRouter:
		if h.onDeliverRouter != nil {
			h.onDeliverRouter(clove.ToHash, msg)
		}
	case DeliveryTunnel:
		if h.onDeliverTunnel != nil {
			h.onDeliverTunnel(clove.TunnelID, clove.ToHash, msg)
		}
	case DeliveryDestination:
		// Would route to destination via tunnel
		if h.onDeliverLocal != nil {
			h.onDeliverLocal(msg)
		}
	}

	return nil
}

// RegisterInboundTag registers a session tag for incoming messages.
func (h *Handler) RegisterInboundTag(tag SessionTag, session Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tagToSession[tag] = session
}

// maintenance performs periodic session cleanup.
func (h *Handler) maintenance() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired sessions.
func (h *Handler) cleanupExpired() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for dest, session := range h.sessions {
		if session.IsExpired() {
			session.Close()
			delete(h.sessions, dest)
		}
	}

	// Clean up tag mappings for expired sessions
	for tag, session := range h.tagToSession {
		if session.IsExpired() {
			delete(h.tagToSession, tag)
		}
	}
}

// generateMsgID generates a random message ID.
func generateMsgID() uint32 {
	var id [4]byte
	rand.Read(id[:])
	return binary.BigEndian.Uint32(id[:])
}

// CreateClove creates a clove for a destination.
func CreateClove(deliveryType DeliveryType, dest data.Hash, tunnelID uint32, payload []byte) *Clove {
	return &Clove{
		DeliveryType: deliveryType,
		TunnelID:     tunnelID,
		ToHash:       dest,
		Payload:      payload,
	}
}

// CreateLocalClove creates a clove for local delivery.
func CreateLocalClove(payload []byte) *Clove {
	return &Clove{
		DeliveryType: DeliveryLocal,
		Payload:      payload,
	}
}

// CreateRouterClove creates a clove for router delivery.
func CreateRouterClove(router data.Hash, payload []byte) *Clove {
	return &Clove{
		DeliveryType: DeliveryRouter,
		ToHash:       router,
		Payload:      payload,
	}
}

// CreateTunnelClove creates a clove for tunnel delivery.
func CreateTunnelClove(gateway data.Hash, tunnelID uint32, payload []byte) *Clove {
	return &Clove{
		DeliveryType: DeliveryTunnel,
		TunnelID:     tunnelID,
		ToHash:       gateway,
		Payload:      payload,
	}
}
