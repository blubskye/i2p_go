package crypto

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20KeySize   = 32
	ChaCha20NonceSize = 12
	ChaCha20TagSize   = 16
)

var (
	ErrChaCha20InvalidNonce = errors.New("crypto: invalid ChaCha20 nonce size")
	ErrChaCha20AuthFailed   = errors.New("crypto: ChaCha20-Poly1305 authentication failed")
)

// ChaCha20Poly1305Encrypt encrypts and authenticates plaintext using ChaCha20-Poly1305.
// Returns ciphertext with appended 16-byte authentication tag.
func ChaCha20Poly1305Encrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != ChaCha20KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrChaCha20InvalidNonce
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Seal appends the ciphertext and tag to nil
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// ChaCha20Poly1305Decrypt decrypts and verifies ciphertext using ChaCha20-Poly1305.
// Ciphertext must include the 16-byte authentication tag.
func ChaCha20Poly1305Decrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != ChaCha20KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrChaCha20InvalidNonce
	}
	if len(ciphertext) < ChaCha20TagSize {
		return nil, ErrDataTooShort
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrChaCha20AuthFailed
	}

	return plaintext, nil
}

// ChaCha20AEAD wraps a ChaCha20-Poly1305 AEAD cipher for repeated use.
type ChaCha20AEAD struct {
	aead cipher.AEAD
}

// NewChaCha20AEAD creates a new ChaCha20-Poly1305 AEAD cipher.
func NewChaCha20AEAD(key []byte) (*ChaCha20AEAD, error) {
	if len(key) != ChaCha20KeySize {
		return nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &ChaCha20AEAD{aead: aead}, nil
}

// Encrypt encrypts and authenticates plaintext.
func (c *ChaCha20AEAD) Encrypt(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrChaCha20InvalidNonce
	}
	return c.aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// Decrypt decrypts and verifies ciphertext.
func (c *ChaCha20AEAD) Decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrChaCha20InvalidNonce
	}
	if len(ciphertext) < ChaCha20TagSize {
		return nil, ErrDataTooShort
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrChaCha20AuthFailed
	}

	return plaintext, nil
}

// NonceSize returns the nonce size (12 bytes).
func (c *ChaCha20AEAD) NonceSize() int {
	return c.aead.NonceSize()
}

// Overhead returns the authentication tag overhead (16 bytes).
func (c *ChaCha20AEAD) Overhead() int {
	return c.aead.Overhead()
}

// NonceFromUint64 creates a 12-byte nonce from a uint64 counter.
// The first 4 bytes are zero, the last 8 bytes are the little-endian counter.
func NonceFromUint64(counter uint64) []byte {
	nonce := make([]byte, ChaCha20NonceSize)
	nonce[4] = byte(counter)
	nonce[5] = byte(counter >> 8)
	nonce[6] = byte(counter >> 16)
	nonce[7] = byte(counter >> 24)
	nonce[8] = byte(counter >> 32)
	nonce[9] = byte(counter >> 40)
	nonce[10] = byte(counter >> 48)
	nonce[11] = byte(counter >> 56)
	return nonce
}
