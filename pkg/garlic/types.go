// Package garlic implements I2P garlic routing.
// Garlic routing bundles multiple encrypted messages together for
// end-to-end encrypted delivery through tunnels.
package garlic

import (
	"errors"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Garlic constants
const (
	// Encryption types
	EncryptionTypeElGamal = 0 // Legacy ElGamal/AES+SessionTags
	EncryptionTypeECIES   = 4 // ECIES-X25519-AEAD-Ratchet

	// Session tag constants
	SessionTagSize      = 32
	MaxSessionTags      = 32
	TagSetDeliveryTime  = 100 * time.Millisecond
	SessionTagExpiry    = 12 * time.Minute

	// Ratchet constants
	MaxRatchetSkip    = 128 // Max skipped keys to store
	RatchetKeyExpiry  = 10 * time.Minute
)

// DeliveryType indicates how a clove should be delivered.
type DeliveryType uint8

const (
	DeliveryLocal       DeliveryType = 0 // Deliver to local destination
	DeliveryDestination DeliveryType = 1 // Deliver to specified destination
	DeliveryRouter      DeliveryType = 2 // Deliver to specified router
	DeliveryTunnel      DeliveryType = 3 // Deliver to specified tunnel
)

// CloveFlags for delivery instructions
const (
	CloveFlagDelay      = 0x10 // Delay requested
	CloveFlagEncrypted  = 0x01 // Clove is encrypted
)

// Clove represents a single message within a garlic message.
type Clove struct {
	DeliveryType DeliveryType
	Delay        uint32       // Delay in seconds (if flag set)
	TunnelID     uint32       // For tunnel delivery
	ToHash       data.Hash    // Destination/router hash
	Payload      []byte       // The encrypted I2NP message
}

// GarlicMessage contains multiple cloves.
type GarlicMessage struct {
	Cloves       []*Clove
	Certificate  uint8
	MsgID        uint32
	Expiration   time.Time
}

// SessionTag is a 32-byte tag for identifying sessions.
type SessionTag [SessionTagSize]byte

// TagSet manages a set of session tags for a session.
type TagSet struct {
	Tags          []SessionTag
	SessionKey    [32]byte
	NextIndex     int
	CreatedAt     time.Time
	NextTag       *SessionTag // For receiving
}

// Session represents an end-to-end encrypted session.
type Session interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	GetNextTag() SessionTag
	AddTags(tags []SessionTag)
	IsExpired() bool
	Close()
}

// Destination represents a garlic-capable destination.
type Destination interface {
	GetIdentHash() data.Hash
	GetEncryptionKey() []byte
	GetEncryptionType() uint16
}

// Errors
var (
	ErrSessionExpired     = errors.New("garlic: session expired")
	ErrNoSessionTag       = errors.New("garlic: no session tag available")
	ErrDecryptionFailed   = errors.New("garlic: decryption failed")
	ErrInvalidClove       = errors.New("garlic: invalid clove")
	ErrRatchetFailed      = errors.New("garlic: ratchet key derivation failed")
	ErrTagNotFound        = errors.New("garlic: session tag not found")
	ErrInvalidPayload     = errors.New("garlic: invalid payload")
)
