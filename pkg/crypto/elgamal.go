package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

const (
	ElGamalPublicKeySize  = 256
	ElGamalPrivateKeySize = 256
	ElGamalPlaintextSize  = 222
	ElGamalCiphertextSize = 514 // 1 + 256 + 1 + 256
)

var (
	ErrElGamalInvalidKey        = errors.New("crypto: invalid ElGamal key size")
	ErrElGamalInvalidPlaintext  = errors.New("crypto: ElGamal plaintext must be 222 bytes")
	ErrElGamalInvalidCiphertext = errors.New("crypto: invalid ElGamal ciphertext")
	ErrElGamalDecryptFailed     = errors.New("crypto: ElGamal decryption hash mismatch")
)

// I2P ElGamal prime (2048-bit)
var elgP = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
	0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
	0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
	0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
	0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
	0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
	0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
	0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
	0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
	0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
	0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
	0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
	0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
	0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
})

// I2P ElGamal generator
var elgG = big.NewInt(2)

// ElGamalKeys represents an ElGamal key pair.
type ElGamalKeys struct {
	publicKey  *big.Int
	privateKey *big.Int
}

// GenerateElGamalKeys generates a new ElGamal key pair.
func GenerateElGamalKeys() (*ElGamalKeys, error) {
	// Generate random private key (256 bytes)
	privBytes := make([]byte, ElGamalPrivateKeySize)
	_, err := rand.Read(privBytes)
	if err != nil {
		return nil, err
	}

	privateKey := new(big.Int).SetBytes(privBytes)

	// publicKey = g^privateKey mod p
	publicKey := new(big.Int).Exp(elgG, privateKey, elgP)

	return &ElGamalKeys{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// NewElGamalKeys creates ElGamal keys from raw bytes.
func NewElGamalKeys(privateKey []byte) (*ElGamalKeys, error) {
	if len(privateKey) != ElGamalPrivateKeySize {
		return nil, ErrElGamalInvalidKey
	}

	priv := new(big.Int).SetBytes(privateKey)
	pub := new(big.Int).Exp(elgG, priv, elgP)

	return &ElGamalKeys{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// PublicKey returns the 256-byte public key.
func (k *ElGamalKeys) PublicKey() []byte {
	return bigIntToBytes(k.publicKey, ElGamalPublicKeySize)
}

// PrivateKey returns the 256-byte private key.
func (k *ElGamalKeys) PrivateKey() []byte {
	return bigIntToBytes(k.privateKey, ElGamalPrivateKeySize)
}

// Encrypt encrypts 222 bytes of plaintext using the public key.
// Returns 514 bytes of ciphertext.
func (k *ElGamalKeys) Encrypt(plaintext []byte) ([]byte, error) {
	return ElGamalEncrypt(k.PublicKey(), plaintext)
}

// Decrypt decrypts 514 bytes of ciphertext using the private key.
// Returns 222 bytes of plaintext.
func (k *ElGamalKeys) Decrypt(ciphertext []byte) ([]byte, error) {
	return ElGamalDecrypt(k.PrivateKey(), ciphertext)
}

// ElGamalEncrypt encrypts 222 bytes of plaintext with a public key.
// Returns 514 bytes: [0x00][a (256 bytes)][0x00][b (256 bytes)]
func ElGamalEncrypt(publicKey, plaintext []byte) ([]byte, error) {
	if len(publicKey) != ElGamalPublicKeySize {
		return nil, ErrElGamalInvalidKey
	}
	if len(plaintext) != ElGamalPlaintextSize {
		return nil, ErrElGamalInvalidPlaintext
	}

	// Generate random k
	kBytes := make([]byte, ElGamalPrivateKeySize)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(kBytes)

	// a = g^k mod p
	a := new(big.Int).Exp(elgG, k, elgP)

	// y = public key
	y := new(big.Int).SetBytes(publicKey)

	// b1 = y^k mod p
	b1 := new(big.Int).Exp(y, k, elgP)

	// Create message m: [0xFF][SHA256(plaintext)][plaintext]
	// Total: 1 + 32 + 222 = 255 bytes
	m := make([]byte, 255)
	m[0] = 0xFF
	hash := sha256.Sum256(plaintext)
	copy(m[1:33], hash[:])
	copy(m[33:], plaintext)

	// Convert m to big.Int
	mInt := new(big.Int).SetBytes(m)

	// b = b1 * m mod p
	b := new(big.Int).Mul(b1, mInt)
	b.Mod(b, elgP)

	// Output: [0x00][a][0x00][b]
	encrypted := make([]byte, ElGamalCiphertextSize)
	encrypted[0] = 0x00
	aBytes := bigIntToBytes(a, 256)
	copy(encrypted[1:257], aBytes)
	encrypted[257] = 0x00
	bBytes := bigIntToBytes(b, 256)
	copy(encrypted[258:514], bBytes)

	return encrypted, nil
}

// ElGamalDecrypt decrypts 514 bytes of ciphertext with a private key.
// Returns 222 bytes of plaintext.
func ElGamalDecrypt(privateKey, ciphertext []byte) ([]byte, error) {
	if len(privateKey) != ElGamalPrivateKeySize {
		return nil, ErrElGamalInvalidKey
	}
	if len(ciphertext) != ElGamalCiphertextSize {
		return nil, ErrElGamalInvalidCiphertext
	}

	// Parse a and b from ciphertext
	// Format: [0x00][a (256 bytes)][0x00][b (256 bytes)]
	a := new(big.Int).SetBytes(ciphertext[1:257])
	b := new(big.Int).SetBytes(ciphertext[258:514])

	// x = private key
	x := new(big.Int).SetBytes(privateKey)

	// Compute x_inv = p - x - 1 (equivalent to -x mod (p-1) for decryption)
	xInv := new(big.Int).Sub(elgP, x)
	xInv.Sub(xInv, big.NewInt(1))

	// Compute a^x_inv mod p
	aToXInv := new(big.Int).Exp(a, xInv, elgP)

	// m = b * a^x_inv mod p
	mInt := new(big.Int).Mul(b, aToXInv)
	mInt.Mod(mInt, elgP)

	// Convert m to bytes (255 bytes)
	m := bigIntToBytes(mInt, 255)

	// Verify hash: m[1:33] should equal SHA256(m[33:])
	expectedHash := sha256.Sum256(m[33:])
	for i := 0; i < 32; i++ {
		if m[1+i] != expectedHash[i] {
			return nil, ErrElGamalDecryptFailed
		}
	}

	// Return plaintext
	plaintext := make([]byte, ElGamalPlaintextSize)
	copy(plaintext, m[33:])

	return plaintext, nil
}

// ElGamalEncryptor provides ElGamal encryption with a stored public key.
type ElGamalEncryptor struct {
	publicKey *big.Int
}

// NewElGamalEncryptor creates an encryptor from a public key.
func NewElGamalEncryptor(publicKey []byte) (*ElGamalEncryptor, error) {
	if len(publicKey) != ElGamalPublicKeySize {
		return nil, ErrElGamalInvalidKey
	}

	return &ElGamalEncryptor{
		publicKey: new(big.Int).SetBytes(publicKey),
	}, nil
}

// Encrypt encrypts plaintext.
func (e *ElGamalEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return ElGamalEncrypt(bigIntToBytes(e.publicKey, ElGamalPublicKeySize), plaintext)
}

// ElGamalDecryptor provides ElGamal decryption with a stored private key.
type ElGamalDecryptor struct {
	privateKey *big.Int
}

// NewElGamalDecryptor creates a decryptor from a private key.
func NewElGamalDecryptor(privateKey []byte) (*ElGamalDecryptor, error) {
	if len(privateKey) != ElGamalPrivateKeySize {
		return nil, ErrElGamalInvalidKey
	}

	return &ElGamalDecryptor{
		privateKey: new(big.Int).SetBytes(privateKey),
	}, nil
}

// Decrypt decrypts ciphertext.
func (d *ElGamalDecryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return ElGamalDecrypt(bigIntToBytes(d.privateKey, ElGamalPrivateKeySize), ciphertext)
}

// bigIntToBytes converts a big.Int to a fixed-size byte slice (big-endian).
func bigIntToBytes(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	result := make([]byte, size)
	copy(result[size-len(b):], b)
	return result
}
