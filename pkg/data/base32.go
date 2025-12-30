package data

import (
	"encoding/base32"
	"strings"
)

// I2P uses lowercase Base32 without padding for .b32.i2p addresses.
const i2pBase32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// I2PBase32Encoding is the I2P-specific Base32 encoding (lowercase, no padding).
var I2PBase32Encoding = base32.NewEncoding(i2pBase32Alphabet).WithPadding(base32.NoPadding)

// Base32Encode encodes data using I2P's Base32 alphabet (lowercase, no padding).
func Base32Encode(data []byte) string {
	return I2PBase32Encoding.EncodeToString(data)
}

// Base32Decode decodes I2P Base32 encoded data.
func Base32Decode(s string) ([]byte, error) {
	// I2P Base32 is case-insensitive, normalize to lowercase
	return I2PBase32Encoding.DecodeString(strings.ToLower(s))
}

// HashToBase32 encodes a Hash as I2P Base32 (for .b32.i2p addresses).
func HashToBase32(h Hash) string {
	return Base32Encode(h[:])
}

// Base32ToHash decodes an I2P Base32 string to a Hash.
func Base32ToHash(s string) (Hash, error) {
	var h Hash
	data, err := Base32Decode(s)
	if err != nil {
		return h, err
	}
	if len(data) != HashSize {
		return h, ErrInvalidHashSize
	}
	copy(h[:], data)
	return h, nil
}

// HashToB32Address returns the .b32.i2p address for a hash.
func HashToB32Address(h Hash) string {
	return HashToBase32(h) + ".b32.i2p"
}

// B32AddressToHash extracts the hash from a .b32.i2p address.
func B32AddressToHash(address string) (Hash, error) {
	// Remove .b32.i2p suffix
	s := strings.TrimSuffix(strings.ToLower(address), ".b32.i2p")
	return Base32ToHash(s)
}
