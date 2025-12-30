package crypto

import (
	"errors"

	"golang.org/x/crypto/curve25519"
)

const (
	X25519KeySize       = 32
	X25519SharedKeySize = 32
)

var (
	ErrX25519InvalidKey = errors.New("crypto: invalid X25519 key size")
	ErrX25519KeyExchange = errors.New("crypto: X25519 key exchange failed")
)

// X25519Keys represents an X25519 key pair for ECDH key exchange.
type X25519Keys struct {
	publicKey  [X25519KeySize]byte
	privateKey [X25519KeySize]byte
}

// GenerateX25519Keys generates a new X25519 key pair.
func GenerateX25519Keys() (*X25519Keys, error) {
	var priv [X25519KeySize]byte

	b, err := RandomBytes(X25519KeySize)
	if err != nil {
		return nil, err
	}
	copy(priv[:], b)

	// Clamp the private key as per X25519 spec
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [X25519KeySize]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return &X25519Keys{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// NewX25519Keys creates X25519 keys from a private key.
func NewX25519Keys(privateKey []byte) (*X25519Keys, error) {
	if len(privateKey) != X25519KeySize {
		return nil, ErrX25519InvalidKey
	}

	var priv [X25519KeySize]byte
	copy(priv[:], privateKey)

	var pub [X25519KeySize]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return &X25519Keys{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// PublicKey returns the 32-byte public key.
func (k *X25519Keys) PublicKey() []byte {
	return k.publicKey[:]
}

// PrivateKey returns the 32-byte private key.
func (k *X25519Keys) PrivateKey() []byte {
	return k.privateKey[:]
}

// SharedSecret computes the shared secret with a remote public key.
func (k *X25519Keys) SharedSecret(remotePublicKey []byte) ([]byte, error) {
	if len(remotePublicKey) != X25519KeySize {
		return nil, ErrX25519InvalidKey
	}

	var remote [X25519KeySize]byte
	copy(remote[:], remotePublicKey)

	var shared [X25519SharedKeySize]byte
	curve25519.ScalarMult(&shared, &k.privateKey, &remote)

	// Check for low-order points (all zeros result)
	allZeros := true
	for _, b := range shared {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return nil, ErrX25519KeyExchange
	}

	return shared[:], nil
}

// X25519 computes a Diffie-Hellman shared secret.
func X25519(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize || len(publicKey) != X25519KeySize {
		return nil, ErrX25519InvalidKey
	}

	shared, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	return shared, nil
}

// X25519ScalarBaseMult computes the public key from a private key.
func X25519ScalarBaseMult(privateKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize {
		return nil, ErrX25519InvalidKey
	}

	var priv, pub [X25519KeySize]byte
	copy(priv[:], privateKey)
	curve25519.ScalarBaseMult(&pub, &priv)

	return pub[:], nil
}

// X25519Basepoint is the standard basepoint for X25519.
var X25519Basepoint = []byte{
	9, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}
