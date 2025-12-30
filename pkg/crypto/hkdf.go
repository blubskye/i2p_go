package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF derives keys using HMAC-based Key Derivation Function (RFC 5869).
// Uses SHA-256 as the hash function.
func HKDF(secret, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	_, err := io.ReadFull(reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// HKDFExtract performs the extract step of HKDF.
// Returns a pseudorandom key of hash length (32 bytes for SHA-256).
func HKDFExtract(salt, secret []byte) []byte {
	return hkdf.Extract(sha256.New, secret, salt)
}

// HKDFExpand performs the expand step of HKDF.
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	reader := hkdf.Expand(sha256.New, prk, info)
	key := make([]byte, length)
	_, err := io.ReadFull(reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// HKDFExpandLabel derives a key using HKDF with a label, similar to TLS 1.3.
// label is prepended with a domain separator.
func HKDFExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// Build the info structure: length (2 bytes) + label length (1 byte) + label + context length (1 byte) + context
	labelBytes := []byte(label)

	info := make([]byte, 2+1+len(labelBytes)+1+len(context))
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(len(labelBytes))
	copy(info[3:], labelBytes)
	info[3+len(labelBytes)] = byte(len(context))
	copy(info[4+len(labelBytes):], context)

	return HKDFExpand(secret, info, length)
}
