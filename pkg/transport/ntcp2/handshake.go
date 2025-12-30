package ntcp2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
)

// Handshake message sizes
const (
	// SessionRequest: X(32) + encrypted options(16) + padding
	SessionRequestMinSize = 64

	// SessionCreated: Y(32) + encrypted options(16) + padding
	SessionCreatedMinSize = 64
)

// Handshaker handles the NTCP2 Noise XK handshake.
type Handshaker struct {
	handshake      *crypto.NoiseHandshake
	localStaticKey *crypto.X25519Keys
	localIdentity  []byte // Serialized RouterInfo

	remoteStaticKey  [32]byte
	remoteIdentHash  data.Hash
	remoteRouterInfo []byte
	remoteEphemeral  []byte

	isInitiator bool
	iv          [16]byte // For AES-CBC in handshake

	// Derived keys for data phase
	SendKey       []byte
	ReceiveKey    []byte
	SendSipKey    []byte
	ReceiveSipKey []byte
}

// NewHandshaker creates a new NTCP2 handshaker.
func NewHandshaker(localStaticKey *crypto.X25519Keys, localIdentity []byte, isInitiator bool) (*Handshaker, error) {
	handshake, err := crypto.NewNoiseHandshake(localStaticKey)
	if err != nil {
		return nil, err
	}

	h := &Handshaker{
		handshake:      handshake,
		localStaticKey: localStaticKey,
		localIdentity:  localIdentity,
		isInitiator:    isInitiator,
	}

	return h, nil
}

// SetRemoteStaticKey sets the remote router's static key (from RouterInfo).
func (h *Handshaker) SetRemoteStaticKey(key []byte) {
	copy(h.remoteStaticKey[:], key)
}

// SetRemoteIdentHash sets the remote router's identity hash.
func (h *Handshaker) SetRemoteIdentHash(hash data.Hash) {
	h.remoteIdentHash = hash
}

// CreateSessionRequest creates the SessionRequest message (Alice → Bob).
// Format: X(32) + encrypted{options(16) + padding}
func (h *Handshaker) CreateSessionRequest(paddingSize int) ([]byte, error) {
	if !h.isInitiator {
		return nil, ErrHandshakeFailed
	}

	// Initialize as initiator with remote static key
	h.handshake.InitiatorInit(h.remoteStaticKey[:], false)

	// Generate random IV
	if _, err := rand.Read(h.iv[:]); err != nil {
		return nil, err
	}

	// Create options payload (16 bytes)
	options := make([]byte, 16)
	options[0] = 2 // Protocol version
	binary.BigEndian.PutUint16(options[1:3], uint16(paddingSize))
	m3p2Len := uint16(len(h.localIdentity) + 32) // RouterInfo + padding estimate
	binary.BigEndian.PutUint16(options[3:5], m3p2Len)
	binary.BigEndian.PutUint32(options[5:9], uint32(time.Now().Unix()))

	// Prepare padding
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	// Plaintext = options + padding
	plaintext := append(options, padding...)

	// Message 1: e, es, encrypted{plaintext}
	// Write ephemeral public key (X)
	x := h.handshake.LocalEphemeral.PublicKey()

	// Mix ephemeral key into hash
	h.handshake.State.MixHash(x)

	// Perform DH: es = DH(e, rs)
	err := h.handshake.MixDH(h.handshake.LocalEphemeral, h.remoteStaticKey[:])
	if err != nil {
		return nil, err
	}

	// Encrypt options with Noise state
	encrypted, err := h.handshake.State.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(encrypted)

	// Combine: X + encrypted{options + padding}
	message := make([]byte, 32+len(encrypted))
	copy(message[0:32], x)
	copy(message[32:], encrypted)

	return message, nil
}

// ProcessSessionRequest processes the SessionRequest message (Bob receives).
func (h *Handshaker) ProcessSessionRequest(message []byte) (paddingLen uint16, clockSkew bool, err error) {
	if h.isInitiator {
		return 0, false, ErrHandshakeFailed
	}

	if len(message) < SessionRequestMinSize {
		return 0, false, ErrInvalidMessage
	}

	// Initialize as responder
	h.handshake.ResponderInit(false)

	// Extract ephemeral key X
	h.remoteEphemeral = make([]byte, 32)
	copy(h.remoteEphemeral, message[0:32])

	// Mix ephemeral into hash
	h.handshake.State.MixHash(h.remoteEphemeral)

	// Perform DH: es = DH(s, re)
	err = h.handshake.MixDH(h.localStaticKey, h.remoteEphemeral)
	if err != nil {
		return 0, false, err
	}

	// Decrypt options
	encrypted := message[32:]
	plaintext, err := h.handshake.State.Decrypt(encrypted)
	if err != nil {
		return 0, false, ErrDecryptionFailed
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(encrypted)

	// Parse options
	if len(plaintext) < 16 {
		return 0, false, ErrInvalidMessage
	}

	version := plaintext[0]
	if version != 2 {
		return 0, false, ErrInvalidMessage
	}

	paddingLen = binary.BigEndian.Uint16(plaintext[1:3])
	timestamp := binary.BigEndian.Uint32(plaintext[5:9])

	// Check clock skew
	now := uint32(time.Now().Unix())
	diff := int64(now) - int64(timestamp)
	if diff < 0 {
		diff = -diff
	}
	clockSkew = diff > int64(ClockSkew.Seconds())

	return paddingLen, clockSkew, nil
}

// CreateSessionCreated creates the SessionCreated message (Bob → Alice).
func (h *Handshaker) CreateSessionCreated(paddingSize int) ([]byte, error) {
	if h.isInitiator {
		return nil, ErrHandshakeFailed
	}

	// Create options (16 bytes)
	options := make([]byte, 16)
	options[0] = 2 // Version
	binary.BigEndian.PutUint16(options[1:3], uint16(paddingSize))
	binary.BigEndian.PutUint32(options[5:9], uint32(time.Now().Unix()))

	// Padding
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	plaintext := append(options, padding...)

	// Message 2: e, ee, encrypted{plaintext}
	y := h.handshake.LocalEphemeral.PublicKey()

	// Mix ephemeral into hash
	h.handshake.State.MixHash(y)

	// Perform DH: ee = DH(e, re)
	err := h.handshake.MixDH(h.handshake.LocalEphemeral, h.remoteEphemeral)
	if err != nil {
		return nil, err
	}

	// Encrypt with current Noise state
	encrypted, err := h.handshake.State.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(encrypted)

	// Combine: Y + encrypted
	message := make([]byte, 32+len(encrypted))
	copy(message[0:32], y)
	copy(message[32:], encrypted)

	return message, nil
}

// ProcessSessionCreated processes the SessionCreated message (Alice receives).
func (h *Handshaker) ProcessSessionCreated(message []byte) (paddingLen uint16, err error) {
	if !h.isInitiator {
		return 0, ErrHandshakeFailed
	}

	if len(message) < SessionCreatedMinSize {
		return 0, ErrInvalidMessage
	}

	// Extract ephemeral key Y
	h.remoteEphemeral = make([]byte, 32)
	copy(h.remoteEphemeral, message[0:32])

	// Mix ephemeral into hash
	h.handshake.State.MixHash(h.remoteEphemeral)

	// Perform DH: ee = DH(e, re)
	err = h.handshake.MixDH(h.handshake.LocalEphemeral, h.remoteEphemeral)
	if err != nil {
		return 0, err
	}

	// Decrypt options
	encrypted := message[32:]
	plaintext, err := h.handshake.State.Decrypt(encrypted)
	if err != nil {
		return 0, ErrDecryptionFailed
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(encrypted)

	// Parse options
	if len(plaintext) < 16 {
		return 0, ErrInvalidMessage
	}

	version := plaintext[0]
	if version != 2 {
		return 0, ErrInvalidMessage
	}

	paddingLen = binary.BigEndian.Uint16(plaintext[1:3])

	return paddingLen, nil
}

// CreateSessionConfirmed creates the SessionConfirmed message (Alice → Bob).
// Part 1: encrypted{static key}
// Part 2: encrypted{RouterInfo + options + padding}
func (h *Handshaker) CreateSessionConfirmed() ([]byte, error) {
	if !h.isInitiator {
		return nil, ErrHandshakeFailed
	}

	// Perform DH: se = DH(s, re) - static to ephemeral
	err := h.handshake.MixDH(h.localStaticKey, h.remoteEphemeral)
	if err != nil {
		return nil, err
	}

	// Part 1: Encrypt static key
	staticPub := h.localStaticKey.PublicKey()
	part1, err := h.handshake.State.Encrypt(staticPub)
	if err != nil {
		return nil, err
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(part1)

	// Part 2: RouterInfo + padding
	part2Payload := make([]byte, 0, len(h.localIdentity)+32)
	part2Payload = append(part2Payload, h.localIdentity...)

	// Add padding to align
	paddingSize := 16 - (len(part2Payload) % 16)
	if paddingSize > 0 && paddingSize < 16 {
		padding := make([]byte, paddingSize)
		rand.Read(padding)
		part2Payload = append(part2Payload, padding...)
	}

	part2, err := h.handshake.State.Encrypt(part2Payload)
	if err != nil {
		return nil, err
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(part2)

	// Derive data phase keys
	h.deriveDataPhaseKeys()

	// Combine parts
	message := append(part1, part2...)
	return message, nil
}

// ProcessSessionConfirmed processes the SessionConfirmed message (Bob receives).
func (h *Handshaker) ProcessSessionConfirmed(message []byte) error {
	if h.isInitiator {
		return ErrHandshakeFailed
	}

	if len(message) < 48 { // Minimum: 32 bytes static + 16 MAC
		return ErrInvalidMessage
	}

	// Perform DH: se = DH(e, rs) - ephemeral to remote static (once decrypted)
	// But first we need to decrypt the static key

	// Part 1: Decrypt static key (32 bytes plaintext + 16 MAC = 48 bytes)
	part1Encrypted := message[:48]
	staticKey, err := h.handshake.State.Decrypt(part1Encrypted)
	if err != nil {
		return ErrDecryptionFailed
	}

	if len(staticKey) != 32 {
		return ErrInvalidMessage
	}

	copy(h.remoteStaticKey[:], staticKey)

	// Update hash with ciphertext
	h.handshake.State.MixHash(part1Encrypted)

	// Now perform DH: se = DH(e, rs)
	err = h.handshake.MixDH(h.handshake.LocalEphemeral, h.remoteStaticKey[:])
	if err != nil {
		return err
	}

	// Part 2: Decrypt RouterInfo
	part2Encrypted := message[48:]
	routerInfo, err := h.handshake.State.Decrypt(part2Encrypted)
	if err != nil {
		return ErrDecryptionFailed
	}

	// Update hash with ciphertext
	h.handshake.State.MixHash(part2Encrypted)

	h.remoteRouterInfo = routerInfo

	// Derive data phase keys
	h.deriveDataPhaseKeys()

	return nil
}

// deriveDataPhaseKeys derives the keys for the data phase.
func (h *Handshaker) deriveDataPhaseKeys() {
	// Get current chaining key from Noise state
	ck := h.handshake.State.GetCK()

	// Derive keys using HKDF
	keyMaterial, _ := crypto.HKDF(nil, ck, []byte("NTCP2"), 64)

	// Split into two 32-byte keys
	if h.isInitiator {
		// Alice: send with first key, receive with second
		h.SendKey = keyMaterial[:32]
		h.ReceiveKey = keyMaterial[32:64]
	} else {
		// Bob: receive with first key, send with second
		h.ReceiveKey = keyMaterial[:32]
		h.SendKey = keyMaterial[32:64]
	}

	// Derive SipHash keys for frame length obfuscation
	sipMaterial, _ := crypto.HKDF(nil, ck, []byte("NTCP2sip"), 32)

	if h.isInitiator {
		h.SendSipKey = sipMaterial[:16]
		h.ReceiveSipKey = sipMaterial[16:32]
	} else {
		h.ReceiveSipKey = sipMaterial[:16]
		h.SendSipKey = sipMaterial[16:32]
	}
}

// GetRemoteRouterInfo returns the remote router's RouterInfo.
func (h *Handshaker) GetRemoteRouterInfo() []byte {
	return h.remoteRouterInfo
}

// VerifyRemoteIdentity verifies the remote router's identity hash matches.
func (h *Handshaker) VerifyRemoteIdentity(expectedHash data.Hash) bool {
	return bytes.Equal(h.remoteIdentHash[:], expectedHash[:])
}

// GetChainingKey returns the current chaining key for debugging.
func (h *Handshaker) GetChainingKey() []byte {
	return h.handshake.State.GetCK()
}
