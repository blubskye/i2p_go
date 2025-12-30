package garlic

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
)

// ElGamalSession implements legacy ElGamal/AES+SessionTags encryption.
type ElGamalSession struct {
	mu sync.Mutex

	destination    data.Hash
	encryptionKey  []byte        // Remote's ElGamal public key
	sessionKey     [32]byte      // Current AES session key
	outboundTags   []SessionTag  // Tags we can use to send
	inboundTags    map[SessionTag][32]byte // Tag -> session key mapping

	createdAt      time.Time
	lastUsed       time.Time
	closed         bool
}

// NewElGamalSession creates a new ElGamal/AES session.
func NewElGamalSession(dest data.Hash, encKey []byte) *ElGamalSession {
	session := &ElGamalSession{
		destination:   dest,
		encryptionKey: encKey,
		outboundTags:  make([]SessionTag, 0, MaxSessionTags),
		inboundTags:   make(map[SessionTag][32]byte),
		createdAt:     time.Now(),
		lastUsed:      time.Now(),
	}

	// Generate initial session key
	rand.Read(session.sessionKey[:])

	return session
}

// Encrypt encrypts data for the destination.
func (s *ElGamalSession) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSessionExpired
	}

	s.lastUsed = time.Now()

	// Check if we have a session tag
	if len(s.outboundTags) > 0 {
		// Use existing session tag
		tag := s.outboundTags[0]
		s.outboundTags = s.outboundTags[1:]

		return s.encryptWithTag(tag, plaintext)
	}

	// No session tag - use ElGamal for initial message
	return s.encryptElGamal(plaintext)
}

// encryptWithTag encrypts using an existing session tag.
func (s *ElGamalSession) encryptWithTag(tag SessionTag, plaintext []byte) ([]byte, error) {
	// Format: SessionTag (32) + AES-encrypted payload
	// AES payload: PayloadLength (2) + Payload + Padding

	// Generate IV from tag
	iv := tag[:16]

	// Encrypt with AES-CBC
	encrypted, err := crypto.AESEncryptCBC(s.sessionKey[:], iv, plaintext)
	if err != nil {
		return nil, err
	}

	// Prepend tag
	result := make([]byte, SessionTagSize+len(encrypted))
	copy(result[:SessionTagSize], tag[:])
	copy(result[SessionTagSize:], encrypted)

	return result, nil
}

// encryptElGamal encrypts the first message using ElGamal.
func (s *ElGamalSession) encryptElGamal(plaintext []byte) ([]byte, error) {
	// ElGamal format:
	// - ElGamal encrypted block (514 bytes): Session key + initial IV
	// - AES encrypted payload

	// Create ElGamal plaintext (256 bytes for 2048-bit key)
	elgPlaintext := make([]byte, 256)
	copy(elgPlaintext[:32], s.sessionKey[:])

	// Random IV
	iv := make([]byte, 16)
	rand.Read(iv)
	copy(elgPlaintext[32:48], iv)

	// Random padding for rest
	rand.Read(elgPlaintext[48:])

	// Encrypt with ElGamal
	elgEncrypted, err := crypto.ElGamalEncrypt(s.encryptionKey, elgPlaintext)
	if err != nil {
		return nil, err
	}

	// Encrypt payload with AES
	aesEncrypted, err := crypto.AESEncryptCBC(s.sessionKey[:], iv, plaintext)
	if err != nil {
		return nil, err
	}

	// Combine
	result := make([]byte, len(elgEncrypted)+len(aesEncrypted))
	copy(result[:len(elgEncrypted)], elgEncrypted)
	copy(result[len(elgEncrypted):], aesEncrypted)

	return result, nil
}

// Decrypt decrypts data received from the destination.
func (s *ElGamalSession) Decrypt(ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSessionExpired
	}

	s.lastUsed = time.Now()

	if len(ciphertext) < SessionTagSize {
		return nil, ErrInvalidPayload
	}

	// Extract session tag
	var tag SessionTag
	copy(tag[:], ciphertext[:SessionTagSize])

	// Look up session key for this tag
	sessionKey, ok := s.inboundTags[tag]
	if !ok {
		return nil, ErrTagNotFound
	}

	// Delete used tag
	delete(s.inboundTags, tag)

	// Decrypt with AES
	iv := tag[:16]
	decrypted, err := crypto.AESDecryptCBC(sessionKey[:], iv, ciphertext[SessionTagSize:])
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// GetNextTag returns the next session tag for sending.
func (s *ElGamalSession) GetNextTag() SessionTag {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.outboundTags) > 0 {
		tag := s.outboundTags[0]
		s.outboundTags = s.outboundTags[1:]
		return tag
	}

	// Generate a new tag
	var tag SessionTag
	rand.Read(tag[:])
	return tag
}

// AddTags adds session tags received from the remote.
func (s *ElGamalSession) AddTags(tags []SessionTag) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.outboundTags = append(s.outboundTags, tags...)
}

// AddInboundTag adds a tag for receiving messages.
func (s *ElGamalSession) AddInboundTag(tag SessionTag, sessionKey [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.inboundTags[tag] = sessionKey
}

// IsExpired returns true if the session has expired.
func (s *ElGamalSession) IsExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.closed || time.Since(s.lastUsed) > SessionTagExpiry
}

// Close closes the session.
func (s *ElGamalSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// GenerateNewTags generates a batch of new session tags.
func (s *ElGamalSession) GenerateNewTags(count int) []SessionTag {
	s.mu.Lock()
	defer s.mu.Unlock()

	tags := make([]SessionTag, count)
	for i := 0; i < count; i++ {
		var tag SessionTag
		rand.Read(tag[:])
		tags[i] = tag
		// Also store for inbound
		s.inboundTags[tag] = s.sessionKey
	}

	return tags
}

// TagCount returns the number of available outbound tags.
func (s *ElGamalSession) TagCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outboundTags)
}
