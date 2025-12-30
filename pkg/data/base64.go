package data

import (
	"encoding/base64"
)

// I2P uses a modified Base64 alphabet:
// Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
// I2P:      ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~
// (+ replaced with -, / replaced with ~)

const i2pBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

// I2PEncoding is the I2P-specific Base64 encoding.
var I2PEncoding = base64.NewEncoding(i2pBase64Alphabet).WithPadding(base64.NoPadding)

// I2PEncodingWithPadding is I2P Base64 with padding.
var I2PEncodingWithPadding = base64.NewEncoding(i2pBase64Alphabet)

// Base64Encode encodes data using I2P's Base64 alphabet (no padding).
func Base64Encode(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

// Base64Decode decodes I2P Base64 encoded data.
func Base64Decode(s string) ([]byte, error) {
	return I2PEncoding.DecodeString(s)
}

// Base64EncodeWithPadding encodes data using I2P's Base64 with padding.
func Base64EncodeWithPadding(data []byte) string {
	return I2PEncodingWithPadding.EncodeToString(data)
}

// Base64DecodeWithPadding decodes I2P Base64 with padding.
func Base64DecodeWithPadding(s string) ([]byte, error) {
	return I2PEncodingWithPadding.DecodeString(s)
}

// Base64EncodedLen returns the length of the base64-encoded string for n bytes.
func Base64EncodedLen(n int) int {
	return I2PEncoding.EncodedLen(n)
}

// Base64DecodedLen returns the maximum decoded length for an encoded string of length n.
func Base64DecodedLen(n int) int {
	return I2PEncoding.DecodedLen(n)
}

// HashToBase64 encodes a Hash as I2P Base64.
func HashToBase64(h Hash) string {
	return Base64Encode(h[:])
}

// Base64ToHash decodes an I2P Base64 string to a Hash.
func Base64ToHash(s string) (Hash, error) {
	var h Hash
	data, err := Base64Decode(s)
	if err != nil {
		return h, err
	}
	if len(data) != HashSize {
		return h, ErrInvalidHashSize
	}
	copy(h[:], data)
	return h, nil
}
