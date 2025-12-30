// Package data provides core I2P data structures.
package data

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const (
	HashSize = 32
)

var (
	ErrInvalidHashSize = errors.New("data: invalid hash size")
)

// Hash represents a 32-byte SHA-256 hash used as an identifier.
// This is the fundamental identifier type in I2P (IdentHash).
type Hash [HashSize]byte

// IdentHash is an alias for Hash, representing the hash of an identity.
type IdentHash = Hash

// NewHash creates a Hash from a byte slice.
func NewHash(data []byte) (Hash, error) {
	var h Hash
	if len(data) != HashSize {
		return h, ErrInvalidHashSize
	}
	copy(h[:], data)
	return h, nil
}

// HashData computes the SHA-256 hash of data.
func HashData(data []byte) Hash {
	return sha256.Sum256(data)
}

// HashMulti computes the SHA-256 hash of multiple data slices.
func HashMulti(data ...[]byte) Hash {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	var result Hash
	copy(result[:], h.Sum(nil))
	return result
}

// Bytes returns the hash as a byte slice.
func (h Hash) Bytes() []byte {
	return h[:]
}

// String returns the hexadecimal representation of the hash.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Short returns an abbreviated string representation (first 8 chars).
func (h Hash) Short() string {
	return h.String()[:8]
}

// IsZero returns true if the hash is all zeros.
func (h Hash) IsZero() bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// Equal returns true if two hashes are equal.
func (h Hash) Equal(other Hash) bool {
	return h == other
}

// XOR returns the XOR of two hashes (for Kademlia distance).
func (h Hash) XOR(other Hash) Hash {
	var result Hash
	for i := 0; i < HashSize; i++ {
		result[i] = h[i] ^ other[i]
	}
	return result
}

// Compare returns -1, 0, or 1 for less than, equal to, or greater than.
func (h Hash) Compare(other Hash) int {
	for i := 0; i < HashSize; i++ {
		if h[i] < other[i] {
			return -1
		}
		if h[i] > other[i] {
			return 1
		}
	}
	return 0
}

// LeadingZeros returns the number of leading zero bits in the hash.
func (h Hash) LeadingZeros() int {
	count := 0
	for _, b := range h {
		if b == 0 {
			count += 8
		} else {
			// Count leading zeros in this byte
			for i := 7; i >= 0; i-- {
				if (b>>i)&1 == 0 {
					count++
				} else {
					return count
				}
			}
		}
	}
	return count
}

// Tag is a generic fixed-size byte array type.
type Tag[T any] interface {
	Bytes() []byte
	String() string
}

// Tag8 is an 8-byte tag.
type Tag8 [8]byte

func (t Tag8) Bytes() []byte   { return t[:] }
func (t Tag8) String() string  { return hex.EncodeToString(t[:]) }

// Tag16 is a 16-byte tag.
type Tag16 [16]byte

func (t Tag16) Bytes() []byte   { return t[:] }
func (t Tag16) String() string  { return hex.EncodeToString(t[:]) }

// Tag32 is a 32-byte tag (same as Hash).
type Tag32 = Hash

// TunnelID is a 4-byte tunnel identifier.
type TunnelID uint32

// MessageID is a 4-byte message identifier.
type MessageID uint32
