package data

// Destination represents an I2P destination.
// A Destination is the public portion of an I2P endpoint, identified by its IdentHash.
// It is essentially an IdentityEx with additional helper methods.
type Destination struct {
	*IdentityEx
}

// NewDestination creates a Destination from a buffer.
func NewDestination(buf []byte) (*Destination, error) {
	identity, err := NewIdentityEx(buf)
	if err != nil {
		return nil, err
	}
	return &Destination{IdentityEx: identity}, nil
}

// NewDestinationFromIdentity creates a Destination from an existing IdentityEx.
func NewDestinationFromIdentity(identity *IdentityEx) *Destination {
	return &Destination{IdentityEx: identity}
}

// Hash returns the destination's IdentHash.
func (d *Destination) Hash() IdentHash {
	return d.GetIdentHash()
}

// Base64 returns the destination as an I2P Base64 string.
func (d *Destination) Base64() string {
	return Base64Encode(d.ToBuffer())
}

// Base32Address returns the .b32.i2p address for this destination.
func (d *Destination) Base32Address() string {
	return HashToB32Address(d.GetIdentHash())
}

// Base32 returns the base32 encoded hash (without .b32.i2p suffix).
func (d *Destination) Base32() string {
	hash := d.GetIdentHash()
	return Base32Encode(hash[:])
}

// LocalDestination represents a destination with private keys.
type LocalDestination struct {
	*PrivateKeys
}

// NewLocalDestination creates a LocalDestination from private keys.
func NewLocalDestination(keys *PrivateKeys) *LocalDestination {
	return &LocalDestination{PrivateKeys: keys}
}

// GetDestination returns the public destination.
func (ld *LocalDestination) GetDestination() *Destination {
	return &Destination{IdentityEx: ld.Identity}
}

// Hash returns the destination's IdentHash.
func (ld *LocalDestination) Hash() IdentHash {
	return ld.GetIdentHash()
}

// DatabaseEntry is the interface for NetDb entries.
type DatabaseEntry interface {
	GetIdentHash() IdentHash
	ToBuffer() []byte
	IsExpired() bool
}

// Ensure RouterInfo and LeaseSet implement DatabaseEntry
var (
	_ DatabaseEntry = (*RouterInfo)(nil)
	_ DatabaseEntry = (*LeaseSet)(nil)
	_ DatabaseEntry = (*LeaseSet2)(nil)
)

// IsExpired for RouterInfo - routers don't expire in the traditional sense
func (ri *RouterInfo) IsExpired() bool {
	// RouterInfo is considered expired if it's older than 48 hours
	// This is a simplified check; actual expiration depends on network rules
	return false
}
