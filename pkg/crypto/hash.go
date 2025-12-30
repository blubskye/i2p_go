package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

// SHA256 computes the SHA-256 hash of data.
func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// SHA256Multi computes the SHA-256 hash of multiple data slices.
func SHA256Multi(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// SHA512 computes the SHA-512 hash of data.
func SHA512(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// HMACSHA256 computes HMAC-SHA256.
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA256Multi computes HMAC-SHA256 of multiple data slices.
func HMACSHA256Multi(key []byte, data ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// HMACSHA256Verify verifies an HMAC-SHA256 tag.
func HMACSHA256Verify(key, data, mac []byte) bool {
	expected := HMACSHA256(key, data)
	return hmac.Equal(expected, mac)
}
