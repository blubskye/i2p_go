package crypto

import (
	"crypto/ed25519"
	"errors"
)

const (
	Ed25519PublicKeySize  = 32
	Ed25519PrivateKeySize = 64 // seed (32) + public key (32)
	Ed25519SeedSize       = 32
	Ed25519SignatureSize  = 64
)

var (
	ErrEd25519InvalidPublicKey  = errors.New("crypto: invalid Ed25519 public key size")
	ErrEd25519InvalidPrivateKey = errors.New("crypto: invalid Ed25519 private key size")
	ErrEd25519InvalidSignature  = errors.New("crypto: invalid Ed25519 signature size")
)

// Ed25519Keys represents an Ed25519 key pair.
type Ed25519Keys struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// GenerateEd25519Keys generates a new Ed25519 key pair.
func GenerateEd25519Keys() (*Ed25519Keys, error) {
	pub, priv, err := ed25519.GenerateKey(RandReader)
	if err != nil {
		return nil, err
	}

	return &Ed25519Keys{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// NewEd25519Keys creates an Ed25519 key pair from a seed.
func NewEd25519Keys(seed []byte) (*Ed25519Keys, error) {
	if len(seed) != Ed25519SeedSize {
		return nil, ErrEd25519InvalidPrivateKey
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return &Ed25519Keys{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// NewEd25519KeysFromPrivate creates Ed25519 keys from a full private key.
func NewEd25519KeysFromPrivate(privateKey []byte) (*Ed25519Keys, error) {
	if len(privateKey) != Ed25519PrivateKeySize {
		return nil, ErrEd25519InvalidPrivateKey
	}

	priv := ed25519.PrivateKey(privateKey)
	pub := priv.Public().(ed25519.PublicKey)

	return &Ed25519Keys{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// PublicKey returns the public key.
func (k *Ed25519Keys) PublicKey() []byte {
	return k.publicKey
}

// PrivateKey returns the full private key (seed + public key).
func (k *Ed25519Keys) PrivateKey() []byte {
	return k.privateKey
}

// Seed returns the 32-byte seed from the private key.
func (k *Ed25519Keys) Seed() []byte {
	return k.privateKey.Seed()
}

// Sign signs data using Ed25519.
func (k *Ed25519Keys) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(k.privateKey, data), nil
}

// SignatureLength returns 64.
func (k *Ed25519Keys) SignatureLength() int {
	return Ed25519SignatureSize
}

// Ed25519Verifier verifies Ed25519 signatures.
type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
}

// NewEd25519Verifier creates a verifier from a public key.
func NewEd25519Verifier(publicKey []byte) (*Ed25519Verifier, error) {
	if len(publicKey) != Ed25519PublicKeySize {
		return nil, ErrEd25519InvalidPublicKey
	}

	return &Ed25519Verifier{
		publicKey: ed25519.PublicKey(publicKey),
	}, nil
}

// Verify verifies an Ed25519 signature.
func (v *Ed25519Verifier) Verify(data, signature []byte) bool {
	if len(signature) != Ed25519SignatureSize {
		return false
	}
	return ed25519.Verify(v.publicKey, data, signature)
}

// PublicKeyLength returns 32.
func (v *Ed25519Verifier) PublicKeyLength() int {
	return Ed25519PublicKeySize
}

// Ed25519Sign signs data with a private key.
func Ed25519Sign(privateKey, data []byte) ([]byte, error) {
	if len(privateKey) != Ed25519PrivateKeySize && len(privateKey) != Ed25519SeedSize {
		return nil, ErrEd25519InvalidPrivateKey
	}

	var priv ed25519.PrivateKey
	if len(privateKey) == Ed25519SeedSize {
		priv = ed25519.NewKeyFromSeed(privateKey)
	} else {
		priv = ed25519.PrivateKey(privateKey)
	}

	return ed25519.Sign(priv, data), nil
}

// Ed25519Verify verifies an Ed25519 signature.
func Ed25519Verify(publicKey, data, signature []byte) bool {
	if len(publicKey) != Ed25519PublicKeySize || len(signature) != Ed25519SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), data, signature)
}
