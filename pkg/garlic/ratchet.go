package garlic

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
	"io"
)

// RatchetSession implements ECIES-X25519-AEAD-Ratchet encryption.
type RatchetSession struct {
	mu sync.Mutex

	destination    data.Hash
	localKeys      *crypto.X25519Keys
	remoteKey      [32]byte      // Remote's static X25519 public key

	// Root key chain
	rootKey        [32]byte

	// Send chain
	sendChainKey   [32]byte
	sendMessageNum uint32

	// Receive chain
	recvChainKey   [32]byte
	recvMessageNum uint32
	skippedKeys    map[uint32][32]byte // messageNum -> key

	// Next header key for receiving
	nextHeaderKey  [32]byte

	// Session tags
	outboundTags   []SessionTag
	inboundTags    map[SessionTag]bool

	createdAt      time.Time
	lastUsed       time.Time
	closed         bool
	initialized    bool
}

// NewRatchetSession creates a new ratchet session.
func NewRatchetSession(dest data.Hash, remoteKey [32]byte) (*RatchetSession, error) {
	localKeys, err := crypto.GenerateX25519Keys()
	if err != nil {
		return nil, err
	}

	session := &RatchetSession{
		destination:  dest,
		localKeys:    localKeys,
		remoteKey:    remoteKey,
		skippedKeys:  make(map[uint32][32]byte),
		outboundTags: make([]SessionTag, 0, MaxSessionTags),
		inboundTags:  make(map[SessionTag]bool),
		createdAt:    time.Now(),
		lastUsed:     time.Now(),
	}

	return session, nil
}

// Initialize performs the initial key exchange.
func (s *RatchetSession) Initialize(isInitiator bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil
	}

	// Perform X25519 key exchange
	sharedSecret, err := s.localKeys.SharedSecret(s.remoteKey[:])
	if err != nil {
		return err
	}

	// Derive initial root key and chain keys using HKDF
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("ratchet"))

	rootKey := make([]byte, 32)
	sendChainKey := make([]byte, 32)
	recvChainKey := make([]byte, 32)

	io.ReadFull(kdf, rootKey)
	io.ReadFull(kdf, sendChainKey)
	io.ReadFull(kdf, recvChainKey)

	copy(s.rootKey[:], rootKey)

	if isInitiator {
		copy(s.sendChainKey[:], sendChainKey)
		copy(s.recvChainKey[:], recvChainKey)
	} else {
		copy(s.sendChainKey[:], recvChainKey)
		copy(s.recvChainKey[:], sendChainKey)
	}

	s.initialized = true
	return nil
}

// Encrypt encrypts data using the ratchet.
func (s *RatchetSession) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSessionExpired
	}

	if !s.initialized {
		if err := s.initializeNoLock(true); err != nil {
			return nil, err
		}
	}

	s.lastUsed = time.Now()

	// Derive message key from chain key
	messageKey, newChainKey := s.deriveMessageKey(s.sendChainKey)
	copy(s.sendChainKey[:], newChainKey)

	// Create header: message number + our ephemeral public key
	header := make([]byte, 4+32)
	header[0] = byte(s.sendMessageNum >> 24)
	header[1] = byte(s.sendMessageNum >> 16)
	header[2] = byte(s.sendMessageNum >> 8)
	header[3] = byte(s.sendMessageNum)
	copy(header[4:], s.localKeys.PublicKey()[:])

	s.sendMessageNum++

	// Encrypt with ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(messageKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	// Format: Nonce + Header + Encrypted(Plaintext)
	ciphertext := aead.Seal(nil, nonce, plaintext, header)

	result := make([]byte, len(nonce)+len(header)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], header)
	copy(result[len(nonce)+len(header):], ciphertext)

	return result, nil
}

// Decrypt decrypts data using the ratchet.
func (s *RatchetSession) Decrypt(ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSessionExpired
	}

	s.lastUsed = time.Now()

	nonceSize := chacha20poly1305.NonceSize
	headerSize := 4 + 32

	if len(ciphertext) < nonceSize+headerSize+chacha20poly1305.Overhead {
		return nil, ErrInvalidPayload
	}

	nonce := ciphertext[:nonceSize]
	header := ciphertext[nonceSize : nonceSize+headerSize]
	encrypted := ciphertext[nonceSize+headerSize:]

	// Parse header
	messageNum := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	var remoteEphemeral [32]byte
	copy(remoteEphemeral[:], header[4:36])

	// Check if we need to update remote key and ratchet
	if remoteEphemeral != s.remoteKey {
		// Perform DH ratchet step
		if err := s.performDHRatchet(remoteEphemeral); err != nil {
			return nil, err
		}
	}

	// Try to get the message key
	messageKey, err := s.getMessageKey(messageNum)
	if err != nil {
		return nil, err
	}

	// Decrypt
	aead, err := chacha20poly1305.New(messageKey[:])
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, encrypted, header)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// initializeNoLock initializes without holding the lock.
func (s *RatchetSession) initializeNoLock(isInitiator bool) error {
	if s.initialized {
		return nil
	}

	// Perform X25519 key exchange
	sharedSecret, err := s.localKeys.SharedSecret(s.remoteKey[:])
	if err != nil {
		return err
	}

	// Derive initial keys using HKDF
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("ratchet"))

	rootKey := make([]byte, 32)
	sendChainKey := make([]byte, 32)
	recvChainKey := make([]byte, 32)

	io.ReadFull(kdf, rootKey)
	io.ReadFull(kdf, sendChainKey)
	io.ReadFull(kdf, recvChainKey)

	copy(s.rootKey[:], rootKey)

	if isInitiator {
		copy(s.sendChainKey[:], sendChainKey)
		copy(s.recvChainKey[:], recvChainKey)
	} else {
		copy(s.sendChainKey[:], recvChainKey)
		copy(s.recvChainKey[:], sendChainKey)
	}

	s.initialized = true
	return nil
}

// deriveMessageKey derives a message key from a chain key.
func (s *RatchetSession) deriveMessageKey(chainKey [32]byte) ([]byte, []byte) {
	kdf := hkdf.New(sha256.New, chainKey[:], nil, []byte("msg"))

	messageKey := make([]byte, 32)
	newChainKey := make([]byte, 32)

	io.ReadFull(kdf, messageKey)
	io.ReadFull(kdf, newChainKey)

	return messageKey, newChainKey
}

// performDHRatchet performs a DH ratchet step.
func (s *RatchetSession) performDHRatchet(newRemoteKey [32]byte) error {
	// Update remote key
	copy(s.remoteKey[:], newRemoteKey[:])

	// Generate new ephemeral key pair
	newKeys, err := crypto.GenerateX25519Keys()
	if err != nil {
		return err
	}
	s.localKeys = newKeys

	// Perform DH
	sharedSecret, err := s.localKeys.SharedSecret(s.remoteKey[:])
	if err != nil {
		return err
	}

	// Derive new root key and receive chain key
	kdf := hkdf.New(sha256.New, append(s.rootKey[:], sharedSecret...), nil, []byte("dhratchet"))

	newRootKey := make([]byte, 32)
	newRecvChainKey := make([]byte, 32)

	io.ReadFull(kdf, newRootKey)
	io.ReadFull(kdf, newRecvChainKey)

	copy(s.rootKey[:], newRootKey)
	copy(s.recvChainKey[:], newRecvChainKey)

	// Reset message counters
	s.recvMessageNum = 0

	return nil
}

// getMessageKey gets or derives the message key for a message number.
func (s *RatchetSession) getMessageKey(messageNum uint32) ([32]byte, error) {
	// Check skipped keys first
	if key, ok := s.skippedKeys[messageNum]; ok {
		delete(s.skippedKeys, messageNum)
		return key, nil
	}

	// Check if message is from the future
	if messageNum > s.recvMessageNum {
		// Store skipped keys
		if messageNum-s.recvMessageNum > MaxRatchetSkip {
			return [32]byte{}, ErrRatchetFailed
		}

		for s.recvMessageNum < messageNum {
			messageKey, newChainKey := s.deriveMessageKey(s.recvChainKey)
			var key [32]byte
			copy(key[:], messageKey)
			s.skippedKeys[s.recvMessageNum] = key
			copy(s.recvChainKey[:], newChainKey)
			s.recvMessageNum++
		}
	}

	// Derive the current key
	messageKey, newChainKey := s.deriveMessageKey(s.recvChainKey)
	copy(s.recvChainKey[:], newChainKey)
	s.recvMessageNum++

	var key [32]byte
	copy(key[:], messageKey)
	return key, nil
}

// GetNextTag returns the next session tag.
func (s *RatchetSession) GetNextTag() SessionTag {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.outboundTags) > 0 {
		tag := s.outboundTags[0]
		s.outboundTags = s.outboundTags[1:]
		return tag
	}

	var tag SessionTag
	rand.Read(tag[:])
	return tag
}

// AddTags adds session tags.
func (s *RatchetSession) AddTags(tags []SessionTag) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outboundTags = append(s.outboundTags, tags...)
}

// IsExpired returns true if the session is expired.
func (s *RatchetSession) IsExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || time.Since(s.lastUsed) > RatchetKeyExpiry
}

// Close closes the session.
func (s *RatchetSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// PublicKey returns our current ephemeral public key.
func (s *RatchetSession) PublicKey() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	var key [32]byte
	copy(key[:], s.localKeys.PublicKey()[:])
	return key
}
