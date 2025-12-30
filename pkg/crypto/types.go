// Package crypto provides cryptographic primitives for I2P.
package crypto

import (
	"crypto/rand"
	"io"
)

// CryptoKeyType represents the encryption key algorithm type.
type CryptoKeyType uint16

const (
	CryptoKeyElGamal              CryptoKeyType = 0
	CryptoKeyECIES_P256           CryptoKeyType = 1
	CryptoKeyECIES_X25519         CryptoKeyType = 4
	CryptoKeyECIES_MLKEM512_X25519  CryptoKeyType = 5
	CryptoKeyECIES_MLKEM768_X25519  CryptoKeyType = 6
	CryptoKeyECIES_MLKEM1024_X25519 CryptoKeyType = 7
)

// SigningKeyType represents the signature algorithm type.
type SigningKeyType uint16

const (
	SigningKeyDSA_SHA1          SigningKeyType = 0
	SigningKeyECDSA_P256        SigningKeyType = 1
	SigningKeyECDSA_P384        SigningKeyType = 2
	SigningKeyECDSA_P521        SigningKeyType = 3
	SigningKeyRSA_SHA256_2048   SigningKeyType = 4
	SigningKeyRSA_SHA384_3072   SigningKeyType = 5
	SigningKeyRSA_SHA512_4096   SigningKeyType = 6
	SigningKeyEdDSA_Ed25519     SigningKeyType = 7
	SigningKeyEdDSA_Ed25519ph   SigningKeyType = 8
	SigningKeyRedDSA_Ed25519    SigningKeyType = 11
)

// Signer signs data.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	SignatureLength() int
	PublicKey() []byte
}

// Verifier verifies signatures.
type Verifier interface {
	Verify(data, signature []byte) bool
	PublicKeyLength() int
}

// Encryptor encrypts data.
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
}

// Decryptor decrypts data.
type Decryptor interface {
	Decrypt(ciphertext []byte) ([]byte, error)
}

// KeyPair represents a public/private key pair.
type KeyPair interface {
	PublicKey() []byte
	PrivateKey() []byte
}

// RandReader is the random number source for crypto operations.
var RandReader io.Reader = rand.Reader

// RandomBytes generates n random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(RandReader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// PublicKeyLength returns the public key length for a signing key type.
func (t SigningKeyType) PublicKeyLength() int {
	switch t {
	case SigningKeyDSA_SHA1:
		return 128
	case SigningKeyECDSA_P256:
		return 64
	case SigningKeyECDSA_P384:
		return 96
	case SigningKeyECDSA_P521:
		return 132
	case SigningKeyEdDSA_Ed25519, SigningKeyEdDSA_Ed25519ph, SigningKeyRedDSA_Ed25519:
		return 32
	default:
		return 0
	}
}

// SignatureLength returns the signature length for a signing key type.
func (t SigningKeyType) SignatureLength() int {
	switch t {
	case SigningKeyDSA_SHA1:
		return 40
	case SigningKeyECDSA_P256:
		return 64
	case SigningKeyECDSA_P384:
		return 96
	case SigningKeyECDSA_P521:
		return 132
	case SigningKeyEdDSA_Ed25519, SigningKeyEdDSA_Ed25519ph, SigningKeyRedDSA_Ed25519:
		return 64
	default:
		return 0
	}
}

// PrivateKeyLength returns the private key length for a signing key type.
func (t SigningKeyType) PrivateKeyLength() int {
	switch t {
	case SigningKeyDSA_SHA1:
		return 20
	case SigningKeyECDSA_P256:
		return 32
	case SigningKeyECDSA_P384:
		return 48
	case SigningKeyECDSA_P521:
		return 66
	case SigningKeyEdDSA_Ed25519, SigningKeyEdDSA_Ed25519ph, SigningKeyRedDSA_Ed25519:
		return 32
	default:
		return 0
	}
}

// PublicKeyLength returns the public encryption key length for a crypto key type.
func (t CryptoKeyType) PublicKeyLength() int {
	switch t {
	case CryptoKeyElGamal:
		return 256
	case CryptoKeyECIES_P256:
		return 64
	case CryptoKeyECIES_X25519:
		return 32
	default:
		return 0
	}
}

// PrivateKeyLength returns the private encryption key length for a crypto key type.
func (t CryptoKeyType) PrivateKeyLength() int {
	switch t {
	case CryptoKeyElGamal:
		return 256
	case CryptoKeyECIES_P256:
		return 32
	case CryptoKeyECIES_X25519:
		return 32
	default:
		return 0
	}
}
