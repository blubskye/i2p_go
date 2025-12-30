package crypto

import (
	"encoding/binary"

	"github.com/dchest/siphash"
)

const (
	SipHashKeySize = 16
)

// SipHash24 computes SipHash-2-4 with a 16-byte key.
func SipHash24(key, data []byte) uint64 {
	if len(key) != SipHashKeySize {
		return 0
	}

	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	return siphash.Hash(k0, k1, data)
}

// SipHasher provides repeated SipHash computations with the same key.
type SipHasher struct {
	k0, k1 uint64
}

// NewSipHasher creates a SipHasher with the given 16-byte key.
func NewSipHasher(key []byte) *SipHasher {
	if len(key) != SipHashKeySize {
		return nil
	}

	return &SipHasher{
		k0: binary.LittleEndian.Uint64(key[0:8]),
		k1: binary.LittleEndian.Uint64(key[8:16]),
	}
}

// Hash computes SipHash-2-4 of the data.
func (s *SipHasher) Hash(data []byte) uint64 {
	return siphash.Hash(s.k0, s.k1, data)
}

// HashUint64 computes SipHash-2-4 of a uint64 value.
func (s *SipHasher) HashUint64(v uint64) uint64 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return siphash.Hash(s.k0, s.k1, buf[:])
}

// NTCP2LengthObfuscate obfuscates the frame length for NTCP2.
// Uses SipHash to generate a mask for the 2-byte length field.
func NTCP2LengthObfuscate(sipKey []byte, iv uint64, length uint16) uint16 {
	hasher := NewSipHasher(sipKey)
	if hasher == nil {
		return length
	}

	mask := hasher.HashUint64(iv)
	return length ^ uint16(mask)
}

// NTCP2LengthDeobfuscate reverses the length obfuscation.
func NTCP2LengthDeobfuscate(sipKey []byte, iv uint64, obfuscated uint16) uint16 {
	// XOR is its own inverse
	return NTCP2LengthObfuscate(sipKey, iv, obfuscated)
}
