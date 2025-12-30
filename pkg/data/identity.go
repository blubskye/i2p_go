package data

import (
	"errors"

	"github.com/go-i2p/go-i2p/pkg/crypto"
)

const (
	// StandardIdentitySize is the size of a standard Identity (387 bytes).
	// PublicKey (256) + SigningKey (128) + Certificate (3)
	StandardIdentitySize = 387

	// PublicKeySize is the size of the ElGamal public key.
	PublicKeySize = 256

	// SigningKeySize is the size of the DSA signing key in standard identity.
	SigningKeySize = 128

	// CertificateMinSize is the minimum certificate size.
	CertificateMinSize = 3
)

// Certificate types
const (
	CertificateTypeNull     = 0
	CertificateTypeHashCash = 1
	CertificateTypeHidden   = 2
	CertificateTypeSigned   = 3
	CertificateTypeMultiple = 4
	CertificateTypeKey      = 5
)

var (
	ErrInvalidIdentity     = errors.New("data: invalid identity")
	ErrInvalidCertificate  = errors.New("data: invalid certificate")
	ErrBufferTooShort      = errors.New("data: buffer too short")
)

// Identity represents the standard I2P identity (387 bytes).
// This is the legacy format used for DSA/ElGamal keys.
type Identity struct {
	PublicKey   [PublicKeySize]byte   // 256 bytes - ElGamal public key
	SigningKey  [SigningKeySize]byte  // 128 bytes - DSA signing key
	Certificate [CertificateMinSize]byte // 3 bytes - type (1) + length (2)
}

// FromBuffer reads an Identity from a byte buffer.
// Returns the number of bytes read.
func (id *Identity) FromBuffer(buf []byte) (int, error) {
	if len(buf) < StandardIdentitySize {
		return 0, ErrBufferTooShort
	}

	copy(id.PublicKey[:], buf[0:PublicKeySize])
	copy(id.SigningKey[:], buf[PublicKeySize:PublicKeySize+SigningKeySize])
	copy(id.Certificate[:], buf[PublicKeySize+SigningKeySize:StandardIdentitySize])

	return StandardIdentitySize, nil
}

// ToBuffer writes the Identity to a byte buffer.
func (id *Identity) ToBuffer() []byte {
	buf := make([]byte, StandardIdentitySize)
	copy(buf[0:PublicKeySize], id.PublicKey[:])
	copy(buf[PublicKeySize:PublicKeySize+SigningKeySize], id.SigningKey[:])
	copy(buf[PublicKeySize+SigningKeySize:], id.Certificate[:])
	return buf
}

// Hash computes the IdentHash of this identity.
func (id *Identity) Hash() IdentHash {
	return HashData(id.ToBuffer())
}

// CertificateType returns the certificate type.
func (id *Identity) CertificateType() byte {
	return id.Certificate[0]
}

// CertificateLength returns the certificate payload length.
func (id *Identity) CertificateLength() uint16 {
	return uint16(id.Certificate[1])<<8 | uint16(id.Certificate[2])
}

// Keys represents the raw key material for an identity.
type Keys struct {
	PrivateKey        [256]byte // ElGamal private key
	SigningPrivateKey [20]byte  // DSA signing private key
	PublicKey         [256]byte // ElGamal public key
	SigningKey        [128]byte // DSA signing public key
}

// Certificate represents an I2P certificate.
type Certificate struct {
	Type    byte
	Length  uint16
	Payload []byte
}

// FromBuffer reads a Certificate from a byte buffer.
func (c *Certificate) FromBuffer(buf []byte) (int, error) {
	if len(buf) < CertificateMinSize {
		return 0, ErrBufferTooShort
	}

	c.Type = buf[0]
	c.Length = uint16(buf[1])<<8 | uint16(buf[2])

	if c.Length > 0 {
		if len(buf) < int(CertificateMinSize+c.Length) {
			return 0, ErrBufferTooShort
		}
		c.Payload = make([]byte, c.Length)
		copy(c.Payload, buf[CertificateMinSize:CertificateMinSize+int(c.Length)])
	}

	return CertificateMinSize + int(c.Length), nil
}

// ToBuffer writes the Certificate to a byte buffer.
func (c *Certificate) ToBuffer() []byte {
	buf := make([]byte, CertificateMinSize+len(c.Payload))
	buf[0] = c.Type
	buf[1] = byte(c.Length >> 8)
	buf[2] = byte(c.Length)
	copy(buf[CertificateMinSize:], c.Payload)
	return buf
}

// Size returns the total size of the certificate.
func (c *Certificate) Size() int {
	return CertificateMinSize + int(c.Length)
}

// KeyCertificate represents a key certificate (type 5) that specifies
// alternative cryptographic algorithms.
type KeyCertificate struct {
	SigningKeyType crypto.SigningKeyType
	CryptoKeyType  crypto.CryptoKeyType
	ExtraData      []byte // Additional key data for algorithms with larger keys
}

// FromCertificate parses a KeyCertificate from a Certificate.
func (kc *KeyCertificate) FromCertificate(c *Certificate) error {
	if c.Type != CertificateTypeKey {
		return ErrInvalidCertificate
	}
	if c.Length < 4 {
		return ErrInvalidCertificate
	}

	kc.SigningKeyType = crypto.SigningKeyType(uint16(c.Payload[0])<<8 | uint16(c.Payload[1]))
	kc.CryptoKeyType = crypto.CryptoKeyType(uint16(c.Payload[2])<<8 | uint16(c.Payload[3]))

	if c.Length > 4 {
		kc.ExtraData = make([]byte, c.Length-4)
		copy(kc.ExtraData, c.Payload[4:])
	}

	return nil
}

// ToCertificate converts the KeyCertificate to a Certificate.
func (kc *KeyCertificate) ToCertificate() *Certificate {
	payloadLen := 4 + len(kc.ExtraData)
	payload := make([]byte, payloadLen)
	payload[0] = byte(kc.SigningKeyType >> 8)
	payload[1] = byte(kc.SigningKeyType)
	payload[2] = byte(kc.CryptoKeyType >> 8)
	payload[3] = byte(kc.CryptoKeyType)
	copy(payload[4:], kc.ExtraData)

	return &Certificate{
		Type:    CertificateTypeKey,
		Length:  uint16(payloadLen),
		Payload: payload,
	}
}

// SigningPublicKeyLength returns the signing public key length for this key certificate.
func (kc *KeyCertificate) SigningPublicKeyLength() int {
	return kc.SigningKeyType.PublicKeyLength()
}

// SigningPrivateKeyLength returns the signing private key length for this key certificate.
func (kc *KeyCertificate) SigningPrivateKeyLength() int {
	return kc.SigningKeyType.PrivateKeyLength()
}

// SignatureLength returns the signature length for this key certificate.
func (kc *KeyCertificate) SignatureLength() int {
	return kc.SigningKeyType.SignatureLength()
}

// CryptoPublicKeyLength returns the encryption public key length.
func (kc *KeyCertificate) CryptoPublicKeyLength() int {
	return kc.CryptoKeyType.PublicKeyLength()
}

// ExtraSigningKeyData returns any extra signing key bytes that overflow
// from the standard 128-byte signing key field.
func (kc *KeyCertificate) ExtraSigningKeyData() int {
	pubKeyLen := kc.SigningPublicKeyLength()
	if pubKeyLen > SigningKeySize {
		return pubKeyLen - SigningKeySize
	}
	return 0
}
