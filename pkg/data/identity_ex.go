package data

import (
	"github.com/go-i2p/go-i2p/pkg/crypto"
)

const (
	// MaxExtendedBufferSize is the maximum size of the extended buffer.
	MaxExtendedBufferSize = 8 // cryptoKeyType (2) + signingKeyType (2) + 4 extra bytes
)

// IdentityEx represents an extended identity that supports multiple crypto types.
// This is the modern format supporting EdDSA, ECDSA, X25519, etc.
type IdentityEx struct {
	StandardIdentity Identity
	ExtendedBuffer   []byte
	identHash        IdentHash
	hashComputed     bool

	// Parsed fields
	signingKeyType crypto.SigningKeyType
	cryptoKeyType  crypto.CryptoKeyType
}

// NewIdentityEx creates a new IdentityEx from a buffer.
func NewIdentityEx(buf []byte) (*IdentityEx, error) {
	id := &IdentityEx{}
	_, err := id.FromBuffer(buf)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// FromBuffer reads an IdentityEx from a byte buffer.
// Returns the number of bytes read.
func (id *IdentityEx) FromBuffer(buf []byte) (int, error) {
	if len(buf) < StandardIdentitySize {
		return 0, ErrBufferTooShort
	}

	// Read the standard identity portion
	n, err := id.StandardIdentity.FromBuffer(buf)
	if err != nil {
		return 0, err
	}

	// Parse certificate to determine extended data
	certType := id.StandardIdentity.CertificateType()
	certLen := id.StandardIdentity.CertificateLength()

	if certType == CertificateTypeKey && certLen > 0 {
		// Key certificate - need to read extended data
		if len(buf) < n+int(certLen) {
			return 0, ErrBufferTooShort
		}

		id.ExtendedBuffer = make([]byte, certLen)
		copy(id.ExtendedBuffer, buf[n:n+int(certLen)])

		// Parse key certificate
		if certLen >= 4 {
			id.signingKeyType = crypto.SigningKeyType(uint16(id.ExtendedBuffer[0])<<8 | uint16(id.ExtendedBuffer[1]))
			id.cryptoKeyType = crypto.CryptoKeyType(uint16(id.ExtendedBuffer[2])<<8 | uint16(id.ExtendedBuffer[3]))
		}

		n += int(certLen)
	} else {
		// Standard identity with null or other certificate
		id.signingKeyType = crypto.SigningKeyDSA_SHA1
		id.cryptoKeyType = crypto.CryptoKeyElGamal
	}

	id.hashComputed = false
	return n, nil
}

// ToBuffer writes the IdentityEx to a byte buffer.
func (id *IdentityEx) ToBuffer() []byte {
	buf := id.StandardIdentity.ToBuffer()
	if len(id.ExtendedBuffer) > 0 {
		buf = append(buf, id.ExtendedBuffer...)
	}
	return buf
}

// FullLen returns the total length of the identity including extended data.
func (id *IdentityEx) FullLen() int {
	return StandardIdentitySize + len(id.ExtendedBuffer)
}

// GetStandardIdentity returns the standard identity portion.
func (id *IdentityEx) GetStandardIdentity() *Identity {
	return &id.StandardIdentity
}

// GetIdentHash returns the IdentHash for this identity.
func (id *IdentityEx) GetIdentHash() IdentHash {
	if !id.hashComputed {
		id.identHash = HashData(id.ToBuffer())
		id.hashComputed = true
	}
	return id.identHash
}

// RecalculateIdentHash forces recalculation of the IdentHash.
func (id *IdentityEx) RecalculateIdentHash() {
	id.identHash = HashData(id.ToBuffer())
	id.hashComputed = true
}

// GetSigningKeyType returns the signing key type.
func (id *IdentityEx) GetSigningKeyType() crypto.SigningKeyType {
	return id.signingKeyType
}

// GetCryptoKeyType returns the encryption key type.
func (id *IdentityEx) GetCryptoKeyType() crypto.CryptoKeyType {
	return id.cryptoKeyType
}

// GetEncryptionPublicKey returns the encryption public key.
// For ElGamal, this is the full 256 bytes from StandardIdentity.PublicKey.
// For X25519, this is 32 bytes extracted from the appropriate location.
func (id *IdentityEx) GetEncryptionPublicKey() []byte {
	switch id.cryptoKeyType {
	case crypto.CryptoKeyElGamal:
		return id.StandardIdentity.PublicKey[:]
	case crypto.CryptoKeyECIES_X25519:
		// X25519 key is stored in the last 32 bytes of the public key field
		return id.StandardIdentity.PublicKey[PublicKeySize-32:]
	case crypto.CryptoKeyECIES_P256:
		// P-256 key is 64 bytes
		return id.StandardIdentity.PublicKey[PublicKeySize-64:]
	default:
		return id.StandardIdentity.PublicKey[:]
	}
}

// GetSigningPublicKey returns the signing public key.
// The location depends on the signing key type.
func (id *IdentityEx) GetSigningPublicKey() []byte {
	keyLen := id.signingKeyType.PublicKeyLength()
	if keyLen == 0 {
		keyLen = SigningKeySize // Default DSA
	}

	if keyLen <= SigningKeySize {
		// Key fits in the standard signing key field
		return id.StandardIdentity.SigningKey[SigningKeySize-keyLen:]
	}

	// Key is larger - combine signing key field and extended buffer
	result := make([]byte, keyLen)
	copy(result, id.StandardIdentity.SigningKey[:])
	if len(id.ExtendedBuffer) > 4 {
		copy(result[SigningKeySize:], id.ExtendedBuffer[4:])
	}
	return result
}

// GetSigningPublicKeyLen returns the length of the signing public key.
func (id *IdentityEx) GetSigningPublicKeyLen() int {
	return id.signingKeyType.PublicKeyLength()
}

// GetSigningPrivateKeyLen returns the length of the signing private key.
func (id *IdentityEx) GetSigningPrivateKeyLen() int {
	return id.signingKeyType.PrivateKeyLength()
}

// GetSignatureLen returns the signature length for this identity's signing key type.
func (id *IdentityEx) GetSignatureLen() int {
	return id.signingKeyType.SignatureLength()
}

// Verify verifies a signature using this identity's public key.
func (id *IdentityEx) Verify(data, signature []byte) bool {
	pubKey := id.GetSigningPublicKey()

	switch id.signingKeyType {
	case crypto.SigningKeyEdDSA_Ed25519, crypto.SigningKeyRedDSA_Ed25519:
		return crypto.Ed25519Verify(pubKey, data, signature)
	// Add other signature types as needed
	default:
		// DSA and ECDSA would need additional implementation
		return false
	}
}

// IsRSA returns true if this identity uses RSA signing.
func (id *IdentityEx) IsRSA() bool {
	switch id.signingKeyType {
	case crypto.SigningKeyRSA_SHA256_2048,
		crypto.SigningKeyRSA_SHA384_3072,
		crypto.SigningKeyRSA_SHA512_4096:
		return true
	default:
		return false
	}
}

// Equal returns true if two identities are equal (same IdentHash).
func (id *IdentityEx) Equal(other *IdentityEx) bool {
	return id.GetIdentHash() == other.GetIdentHash()
}

// PrivateKeys holds the private key material for an identity.
type PrivateKeys struct {
	Identity          *IdentityEx
	EncryptionPrivKey []byte // Private key for decryption
	SigningPrivKey    []byte // Private key for signing
}

// NewPrivateKeys creates PrivateKeys from raw key material.
func NewPrivateKeys(identity *IdentityEx, encryptionPriv, signingPriv []byte) *PrivateKeys {
	return &PrivateKeys{
		Identity:          identity,
		EncryptionPrivKey: encryptionPriv,
		SigningPrivKey:    signingPriv,
	}
}

// Sign signs data using the private signing key.
func (pk *PrivateKeys) Sign(data []byte) ([]byte, error) {
	switch pk.Identity.GetSigningKeyType() {
	case crypto.SigningKeyEdDSA_Ed25519, crypto.SigningKeyRedDSA_Ed25519:
		return crypto.Ed25519Sign(pk.SigningPrivKey, data)
	default:
		return nil, ErrInvalidIdentity
	}
}

// Decrypt decrypts data using the private encryption key.
func (pk *PrivateKeys) Decrypt(ciphertext []byte) ([]byte, error) {
	switch pk.Identity.GetCryptoKeyType() {
	case crypto.CryptoKeyElGamal:
		return crypto.ElGamalDecrypt(pk.EncryptionPrivKey, ciphertext)
	case crypto.CryptoKeyECIES_X25519:
		// X25519-based decryption would be implemented here
		return nil, ErrInvalidIdentity
	default:
		return nil, ErrInvalidIdentity
	}
}

// GetIdentHash returns the IdentHash of the public identity.
func (pk *PrivateKeys) GetIdentHash() IdentHash {
	return pk.Identity.GetIdentHash()
}

// ToBytes serializes the private keys to bytes.
// Format: IdentityEx || SigningPrivKey || EncryptionPrivKey
func (pk *PrivateKeys) ToBytes() []byte {
	identBytes := pk.Identity.ToBuffer()
	result := make([]byte, len(identBytes)+len(pk.SigningPrivKey)+len(pk.EncryptionPrivKey))
	offset := 0
	copy(result[offset:], identBytes)
	offset += len(identBytes)
	copy(result[offset:], pk.SigningPrivKey)
	offset += len(pk.SigningPrivKey)
	copy(result[offset:], pk.EncryptionPrivKey)
	return result
}

// NewPrivateKeysFromBytes parses PrivateKeys from bytes.
// Format: IdentityEx || SigningPrivKey || EncryptionPrivKey
func NewPrivateKeysFromBytes(data []byte) (*PrivateKeys, error) {
	if len(data) < 387 { // Minimum identity size
		return nil, ErrInvalidIdentity
	}

	// Parse the identity first
	identity, err := NewIdentityEx(data)
	if err != nil {
		return nil, err
	}

	identLen := identity.FullLen()
	if identLen <= 0 || len(data) < identLen {
		return nil, ErrInvalidIdentity
	}

	remaining := data[identLen:]

	// Determine key sizes based on identity type
	sigKeySize := 32  // Ed25519 private key size
	encKeySize := 32  // X25519 private key size

	if len(remaining) < sigKeySize+encKeySize {
		return nil, ErrInvalidIdentity
	}

	return &PrivateKeys{
		Identity:          identity,
		SigningPrivKey:    remaining[:sigKeySize],
		EncryptionPrivKey: remaining[sigKeySize : sigKeySize+encKeySize],
	}, nil
}
