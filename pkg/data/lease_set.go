package data

import (
	"encoding/binary"
	"errors"
	"time"
)

// LeaseSet constants
const (
	MaxLeases     = 16
	LeaseSize     = 44 // Hash (32) + TunnelID (4) + EndDate (8)
)

var (
	ErrInvalidLeaseSet = errors.New("data: invalid lease set")
	ErrTooManyLeases   = errors.New("data: too many leases")
)

// Lease represents a single lease (tunnel endpoint) in a LeaseSet.
type Lease struct {
	TunnelGateway IdentHash // Router hash of the tunnel gateway
	TunnelID      TunnelID  // Tunnel ID at the gateway
	EndDate       int64     // Expiration time in milliseconds
}

// FromBuffer reads a Lease from a byte buffer.
func (l *Lease) FromBuffer(buf []byte) error {
	if len(buf) < LeaseSize {
		return ErrBufferTooShort
	}

	copy(l.TunnelGateway[:], buf[0:32])
	l.TunnelID = TunnelID(binary.BigEndian.Uint32(buf[32:36]))
	l.EndDate = int64(binary.BigEndian.Uint64(buf[36:44]))

	return nil
}

// ToBuffer writes the Lease to a byte buffer.
func (l *Lease) ToBuffer() []byte {
	buf := make([]byte, LeaseSize)
	copy(buf[0:32], l.TunnelGateway[:])
	binary.BigEndian.PutUint32(buf[32:36], uint32(l.TunnelID))
	binary.BigEndian.PutUint64(buf[36:44], uint64(l.EndDate))
	return buf
}

// IsExpired returns true if this lease has expired.
func (l *Lease) IsExpired() bool {
	return time.Now().UnixMilli() > l.EndDate
}

// GetEndTime returns the end time as time.Time.
func (l *Lease) GetEndTime() time.Time {
	return time.UnixMilli(l.EndDate)
}

// LeaseSet represents an I2P LeaseSet (version 1).
type LeaseSet struct {
	Destination    *IdentityEx
	EncryptionKey  []byte // 256 bytes for ElGamal
	SigningKey     []byte // Public signing key
	Leases         []*Lease
	Signature      []byte

	// Computed
	identHash    IdentHash
	hashComputed bool
	expirationTime int64
}

// NewLeaseSet creates a new LeaseSet from a buffer.
func NewLeaseSet(buf []byte) (*LeaseSet, error) {
	ls := &LeaseSet{}
	_, err := ls.FromBuffer(buf)
	if err != nil {
		return nil, err
	}
	return ls, nil
}

// FromBuffer parses a LeaseSet from a byte buffer.
func (ls *LeaseSet) FromBuffer(buf []byte) (int, error) {
	offset := 0

	// Parse destination identity
	ls.Destination = &IdentityEx{}
	n, err := ls.Destination.FromBuffer(buf[offset:])
	if err != nil {
		return 0, err
	}
	offset += n

	// Parse encryption key (256 bytes for ElGamal)
	encKeyLen := 256
	if len(buf) < offset+encKeyLen {
		return 0, ErrBufferTooShort
	}
	ls.EncryptionKey = make([]byte, encKeyLen)
	copy(ls.EncryptionKey, buf[offset:offset+encKeyLen])
	offset += encKeyLen

	// Parse signing key (size depends on destination's signing key type)
	sigKeyLen := ls.Destination.GetSigningPublicKeyLen()
	if sigKeyLen == 0 {
		sigKeyLen = 128 // Default DSA
	}
	if len(buf) < offset+sigKeyLen {
		return 0, ErrBufferTooShort
	}
	ls.SigningKey = make([]byte, sigKeyLen)
	copy(ls.SigningKey, buf[offset:offset+sigKeyLen])
	offset += sigKeyLen

	// Parse number of leases
	if len(buf) < offset+1 {
		return 0, ErrBufferTooShort
	}
	numLeases := int(buf[offset])
	offset++

	if numLeases > MaxLeases {
		return 0, ErrTooManyLeases
	}

	// Parse leases
	ls.Leases = make([]*Lease, 0, numLeases)
	for i := 0; i < numLeases; i++ {
		if len(buf) < offset+LeaseSize {
			return 0, ErrBufferTooShort
		}
		lease := &Lease{}
		if err := lease.FromBuffer(buf[offset:]); err != nil {
			return 0, err
		}
		ls.Leases = append(ls.Leases, lease)
		offset += LeaseSize
	}

	// Parse signature
	sigLen := ls.Destination.GetSignatureLen()
	if sigLen == 0 {
		sigLen = 40 // Default DSA
	}
	if len(buf) < offset+sigLen {
		return 0, ErrBufferTooShort
	}
	ls.Signature = make([]byte, sigLen)
	copy(ls.Signature, buf[offset:offset+sigLen])
	offset += sigLen

	ls.computeExpiration()

	return offset, nil
}

// computeExpiration finds the earliest lease expiration.
func (ls *LeaseSet) computeExpiration() {
	ls.expirationTime = 0
	for _, lease := range ls.Leases {
		if ls.expirationTime == 0 || lease.EndDate < ls.expirationTime {
			ls.expirationTime = lease.EndDate
		}
	}
}

// GetIdentHash returns the destination's IdentHash.
func (ls *LeaseSet) GetIdentHash() IdentHash {
	if !ls.hashComputed {
		ls.identHash = ls.Destination.GetIdentHash()
		ls.hashComputed = true
	}
	return ls.identHash
}

// GetExpirationTime returns the earliest lease expiration.
func (ls *LeaseSet) GetExpirationTime() int64 {
	return ls.expirationTime
}

// IsExpired returns true if all leases have expired.
func (ls *LeaseSet) IsExpired() bool {
	now := time.Now().UnixMilli()
	return ls.expirationTime <= now
}

// GetNonExpiredLeases returns all non-expired leases.
func (ls *LeaseSet) GetNonExpiredLeases() []*Lease {
	now := time.Now().UnixMilli()
	result := make([]*Lease, 0, len(ls.Leases))
	for _, lease := range ls.Leases {
		if lease.EndDate > now {
			result = append(result, lease)
		}
	}
	return result
}

// Verify verifies the LeaseSet signature.
func (ls *LeaseSet) Verify() bool {
	// TODO: Implement signature verification
	return true
}

// ToBuffer serializes the LeaseSet to a byte buffer.
func (ls *LeaseSet) ToBuffer() []byte {
	// Calculate total size
	encKeyLen := len(ls.EncryptionKey)
	sigKeyLen := len(ls.SigningKey)
	sigLen := len(ls.Signature)

	size := ls.Destination.FullLen() + encKeyLen + sigKeyLen + 1 + len(ls.Leases)*LeaseSize + sigLen
	buf := make([]byte, size)
	offset := 0

	// Write destination
	destBuf := ls.Destination.ToBuffer()
	copy(buf[offset:], destBuf)
	offset += len(destBuf)

	// Write encryption key
	copy(buf[offset:], ls.EncryptionKey)
	offset += encKeyLen

	// Write signing key
	copy(buf[offset:], ls.SigningKey)
	offset += sigKeyLen

	// Write number of leases
	buf[offset] = byte(len(ls.Leases))
	offset++

	// Write leases
	for _, lease := range ls.Leases {
		copy(buf[offset:], lease.ToBuffer())
		offset += LeaseSize
	}

	// Write signature
	copy(buf[offset:], ls.Signature)

	return buf
}

// LeaseSet2Type represents the type of LeaseSet2.
type LeaseSet2Type uint8

const (
	LeaseSet2TypeStandard   LeaseSet2Type = 3
	LeaseSet2TypeEncrypted  LeaseSet2Type = 5
	LeaseSet2TypeMeta       LeaseSet2Type = 7
)

// LeaseSet2 represents an I2P LeaseSet2 (modern format).
type LeaseSet2 struct {
	Type           LeaseSet2Type
	Destination    *IdentityEx
	Published      int64 // Seconds since epoch
	Expires        uint16 // Seconds after published
	Flags          uint16
	EncryptionKeys [][]byte // Multiple encryption keys possible
	Leases         []*Lease
	Signature      []byte

	// For encrypted LeaseSet2
	OuterCiphertext []byte

	// Computed
	identHash    IdentHash
	hashComputed bool
}

// NewLeaseSet2 creates a new LeaseSet2 from a buffer.
func NewLeaseSet2(buf []byte) (*LeaseSet2, error) {
	ls := &LeaseSet2{}
	_, err := ls.FromBuffer(buf)
	if err != nil {
		return nil, err
	}
	return ls, nil
}

// FromBuffer parses a LeaseSet2 from a byte buffer.
func (ls *LeaseSet2) FromBuffer(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, ErrBufferTooShort
	}

	offset := 0

	// Type is the first byte
	ls.Type = LeaseSet2Type(buf[offset])
	offset++

	// Parse destination
	ls.Destination = &IdentityEx{}
	n, err := ls.Destination.FromBuffer(buf[offset:])
	if err != nil {
		return 0, err
	}
	offset += n

	// Published timestamp (4 bytes)
	if len(buf) < offset+4 {
		return 0, ErrBufferTooShort
	}
	ls.Published = int64(binary.BigEndian.Uint32(buf[offset:])) // Seconds
	offset += 4

	// Expires (2 bytes, seconds after published)
	if len(buf) < offset+2 {
		return 0, ErrBufferTooShort
	}
	ls.Expires = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	// Flags (2 bytes)
	if len(buf) < offset+2 {
		return 0, ErrBufferTooShort
	}
	ls.Flags = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	// Properties (variable length mapping, skipped for now)
	if len(buf) < offset+2 {
		return 0, ErrBufferTooShort
	}
	propsLen := int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2 + propsLen

	// Number of encryption keys
	if len(buf) < offset+1 {
		return 0, ErrBufferTooShort
	}
	numKeys := int(buf[offset])
	offset++

	// Parse encryption keys
	ls.EncryptionKeys = make([][]byte, 0, numKeys)
	for i := 0; i < numKeys; i++ {
		if len(buf) < offset+4 {
			return 0, ErrBufferTooShort
		}
		// Encryption type (2 bytes)
		// encType := binary.BigEndian.Uint16(buf[offset:])
		offset += 2
		// Key length (2 bytes)
		keyLen := int(binary.BigEndian.Uint16(buf[offset:]))
		offset += 2
		if len(buf) < offset+keyLen {
			return 0, ErrBufferTooShort
		}
		key := make([]byte, keyLen)
		copy(key, buf[offset:offset+keyLen])
		ls.EncryptionKeys = append(ls.EncryptionKeys, key)
		offset += keyLen
	}

	// Number of leases
	if len(buf) < offset+1 {
		return 0, ErrBufferTooShort
	}
	numLeases := int(buf[offset])
	offset++

	// Parse leases (40 bytes each for LeaseSet2: Hash + TunnelID + EndDate)
	lease2Size := 40 // Hash (32) + TunnelID (4) + EndDate (4 bytes seconds)
	ls.Leases = make([]*Lease, 0, numLeases)
	for i := 0; i < numLeases; i++ {
		if len(buf) < offset+lease2Size {
			return 0, ErrBufferTooShort
		}
		lease := &Lease{}
		copy(lease.TunnelGateway[:], buf[offset:offset+32])
		lease.TunnelID = TunnelID(binary.BigEndian.Uint32(buf[offset+32:]))
		// EndDate is 4 bytes (seconds) in LeaseSet2
		endDateSecs := binary.BigEndian.Uint32(buf[offset+36:])
		lease.EndDate = int64(endDateSecs) * 1000 // Convert to milliseconds
		ls.Leases = append(ls.Leases, lease)
		offset += lease2Size
	}

	// Parse signature
	sigLen := ls.Destination.GetSignatureLen()
	if sigLen == 0 {
		sigLen = 64 // Default Ed25519
	}
	if len(buf) < offset+sigLen {
		return 0, ErrBufferTooShort
	}
	ls.Signature = make([]byte, sigLen)
	copy(ls.Signature, buf[offset:offset+sigLen])
	offset += sigLen

	return offset, nil
}

// GetIdentHash returns the destination's IdentHash.
func (ls *LeaseSet2) GetIdentHash() IdentHash {
	if !ls.hashComputed {
		ls.identHash = ls.Destination.GetIdentHash()
		ls.hashComputed = true
	}
	return ls.identHash
}

// GetExpirationTime returns the expiration time in milliseconds.
func (ls *LeaseSet2) GetExpirationTime() int64 {
	return (ls.Published + int64(ls.Expires)) * 1000
}

// IsExpired returns true if the LeaseSet2 has expired.
func (ls *LeaseSet2) IsExpired() bool {
	return time.Now().UnixMilli() > ls.GetExpirationTime()
}

// ToBuffer serializes the LeaseSet2 to a byte buffer.
func (ls *LeaseSet2) ToBuffer() []byte {
	// TODO: Implement full serialization
	return nil
}
