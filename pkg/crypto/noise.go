package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrNoiseDecryptFailed = errors.New("crypto: Noise decryption failed")
)

// NoiseSymmetricState holds the symmetric state for Noise protocol handshakes.
// This implements the symmetric cryptographic operations used in Noise_XK, Noise_IK, etc.
type NoiseSymmetricState struct {
	H  [32]byte // Handshake hash
	CK [64]byte // CK (32 bytes) + K (32 bytes) - chaining key and encryption key
	N  uint64   // Nonce counter
}

// NTCP2 protocol name: "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
var (
	// Pre-computed SHA256("Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256")
	ntcp2ProtocolNameHash = [32]byte{
		0x72, 0xe8, 0x42, 0xc5, 0x45, 0xe1, 0x80, 0x80, 0xd3, 0x9c, 0x44, 0x93, 0xbb, 0x91, 0xd7, 0xed,
		0xf2, 0x28, 0x98, 0x17, 0x71, 0x21, 0x8c, 0x1f, 0x62, 0x4e, 0x20, 0x6f, 0x28, 0xd3, 0x2f, 0x71,
	}
	// SHA256(ntcp2ProtocolNameHash)
	ntcp2HH = [32]byte{
		0x49, 0xff, 0x48, 0x3f, 0xc4, 0x04, 0xb9, 0xb2, 0x6b, 0x11, 0x94, 0x36, 0x72, 0xff, 0x05, 0xb5,
		0x61, 0x27, 0x03, 0x31, 0xba, 0x89, 0xb8, 0xfc, 0x33, 0x15, 0x93, 0x87, 0x57, 0xdd, 0x3d, 0x1e,
	}
)

// SSU2 protocol name: "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"
var (
	// Pre-computed SHA256("Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256")
	ssu2ProtocolNameHash = [32]byte{
		0xb1, 0x37, 0x22, 0x81, 0x74, 0x23, 0xa8, 0xfd, 0xf4, 0x2d, 0xf2, 0xe6, 0x0e, 0xd1, 0xed, 0xf4,
		0x1b, 0x93, 0x07, 0x1d, 0xb1, 0xec, 0x24, 0xa3, 0x67, 0xf7, 0x84, 0xec, 0x27, 0x0d, 0x81, 0x32,
	}
	// SHA256(ssu2ProtocolNameHash)
	ssu2HH = [32]byte{
		0xdc, 0x85, 0xe6, 0xaf, 0x7b, 0x02, 0x65, 0x0c, 0xf1, 0xf9, 0x0d, 0x71, 0xfb, 0xc6, 0xd4, 0x53,
		0xa7, 0xcf, 0x6d, 0xbf, 0xbd, 0x52, 0x5e, 0xa5, 0xb5, 0x79, 0x1c, 0x47, 0xb3, 0x5e, 0xbc, 0x33,
	}
)

// Noise_N protocol name: "Noise_N_25519_ChaChaPoly_SHA256"
var (
	noiseNProtocolName = []byte("Noise_N_25519_ChaChaPoly_SHA256\x00") // 32 bytes with null padding
	// SHA256("Noise_N_25519_ChaChaPoly_SHA256" || 0)
	noiseNHH = [32]byte{
		0x69, 0x4d, 0x52, 0x44, 0x5a, 0x27, 0xd9, 0xad, 0xfa, 0xd2, 0x9c, 0x76, 0x32, 0x39, 0x5d, 0xc1,
		0xe4, 0x35, 0x4c, 0x69, 0xb4, 0xf9, 0x2e, 0xac, 0x8a, 0x1e, 0xe4, 0x6a, 0x9e, 0xd2, 0x15, 0x54,
	}
)

// Noise_IK protocol name: "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"
var (
	noiseIKProtocolNameHash = [32]byte{
		0x4c, 0xaf, 0x11, 0xef, 0x2c, 0x8e, 0x36, 0x56, 0x4c, 0x53, 0xe8, 0x88, 0x85, 0x06, 0x4d, 0xba,
		0xac, 0xbe, 0x00, 0x54, 0xad, 0x17, 0x8f, 0x80, 0x79, 0xa6, 0x46, 0x82, 0x7e, 0x6e, 0xe4, 0x0c,
	}
	noiseIKHH = [32]byte{
		0x9c, 0xcf, 0x85, 0x2c, 0xc9, 0x3b, 0xb9, 0x50, 0x44, 0x41, 0xe9, 0x50, 0xe0, 0x1d, 0x52, 0x32,
		0x2e, 0x0d, 0x47, 0xad, 0x93, 0x5a, 0x9f, 0x73, 0x9e, 0x50, 0x73, 0xb5, 0x13, 0x7b, 0xd9, 0x64,
	}
)

// Init initializes the Noise symmetric state.
// ck is the initial chaining key (protocol name hash or padded protocol name).
// hh is SHA256(ck).
// pub is the remote static public key (32 bytes for X25519).
func (s *NoiseSymmetricState) Init(ck, hh, pub []byte) {
	// Set CK to the protocol name hash
	copy(s.CK[:32], ck)

	// H = SHA256(hh || pub)
	h := sha256.New()
	h.Write(hh)
	h.Write(pub)
	copy(s.H[:], h.Sum(nil))

	s.N = 0
}

// InitNTCP2 initializes state for NTCP2 (Noise_XKaesobfse+hs2+hs3).
func (s *NoiseSymmetricState) InitNTCP2(remoteStaticKey []byte) {
	s.Init(ntcp2ProtocolNameHash[:], ntcp2HH[:], remoteStaticKey)
}

// InitSSU2 initializes state for SSU2 (Noise_XKchaobfse+hs1+hs2+hs3).
func (s *NoiseSymmetricState) InitSSU2(remoteStaticKey []byte) {
	s.Init(ssu2ProtocolNameHash[:], ssu2HH[:], remoteStaticKey)
}

// InitNoiseN initializes state for Noise_N pattern (tunnels, router).
func (s *NoiseSymmetricState) InitNoiseN(remoteStaticKey []byte) {
	s.Init(noiseNProtocolName, noiseNHH[:], remoteStaticKey)
}

// InitNoiseIK initializes state for Noise_IK pattern (ratchets).
func (s *NoiseSymmetricState) InitNoiseIK(remoteStaticKey []byte) {
	s.Init(noiseIKProtocolNameHash[:], noiseIKHH[:], remoteStaticKey)
}

// MixHash updates h = SHA256(h || data).
func (s *NoiseSymmetricState) MixHash(data []byte) {
	h := sha256.New()
	h.Write(s.H[:])
	h.Write(data)
	copy(s.H[:], h.Sum(nil))
}

// MixHashMulti updates h = SHA256(h || data1 || data2 || ...).
func (s *NoiseSymmetricState) MixHashMulti(data ...[]byte) {
	h := sha256.New()
	h.Write(s.H[:])
	for _, d := range data {
		h.Write(d)
	}
	copy(s.H[:], h.Sum(nil))
}

// MixKey performs key derivation: (CK, K) = HKDF(CK, sharedSecret).
// After this call, CK[:32] is the new chaining key and CK[32:64] is the encryption key.
func (s *NoiseSymmetricState) MixKey(sharedSecret []byte) error {
	// HKDF with CK as salt and sharedSecret as input key material
	out, err := HKDF(sharedSecret, s.CK[:32], nil, 64)
	if err != nil {
		return err
	}
	copy(s.CK[:], out)
	s.N = 0
	return nil
}

// GetCK returns the current chaining key (first 32 bytes).
func (s *NoiseSymmetricState) GetCK() []byte {
	return s.CK[:32]
}

// GetKey returns the current encryption key (bytes 32-64).
func (s *NoiseSymmetricState) GetKey() []byte {
	return s.CK[32:64]
}

// GetH returns the current handshake hash.
func (s *NoiseSymmetricState) GetH() []byte {
	return s.H[:]
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with H as associated data.
// Returns ciphertext with 16-byte authentication tag appended.
func (s *NoiseSymmetricState) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := s.makeNonce()

	aead, err := chacha20poly1305.New(s.CK[32:64])
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, s.H[:])
	s.N++

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 with H as associated data.
// Ciphertext must include the 16-byte authentication tag.
func (s *NoiseSymmetricState) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrNoiseDecryptFailed
	}

	nonce := s.makeNonce()

	aead, err := chacha20poly1305.New(s.CK[32:64])
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, s.H[:])
	if err != nil {
		return nil, ErrNoiseDecryptFailed
	}

	s.N++
	return plaintext, nil
}

// EncryptWithAD encrypts with custom associated data.
func (s *NoiseSymmetricState) EncryptWithAD(plaintext, ad []byte) ([]byte, error) {
	nonce := s.makeNonce()

	aead, err := chacha20poly1305.New(s.CK[32:64])
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, ad)
	s.N++

	return ciphertext, nil
}

// DecryptWithAD decrypts with custom associated data.
func (s *NoiseSymmetricState) DecryptWithAD(ciphertext, ad []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrNoiseDecryptFailed
	}

	nonce := s.makeNonce()

	aead, err := chacha20poly1305.New(s.CK[32:64])
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrNoiseDecryptFailed
	}

	s.N++
	return plaintext, nil
}

// makeNonce creates a 12-byte nonce from the counter N.
// Format: [4 zero bytes][8-byte little-endian N]
func (s *NoiseSymmetricState) makeNonce() []byte {
	nonce := make([]byte, 12)
	if s.N > 0 {
		binary.LittleEndian.PutUint64(nonce[4:], s.N)
	}
	return nonce
}

// Clone creates a copy of the state.
func (s *NoiseSymmetricState) Clone() *NoiseSymmetricState {
	clone := &NoiseSymmetricState{
		N: s.N,
	}
	copy(clone.H[:], s.H[:])
	copy(clone.CK[:], s.CK[:])
	return clone
}

// Reset clears the state.
func (s *NoiseSymmetricState) Reset() {
	for i := range s.H {
		s.H[i] = 0
	}
	for i := range s.CK {
		s.CK[i] = 0
	}
	s.N = 0
}

// NoiseHandshake provides high-level handshake operations.
type NoiseHandshake struct {
	State         *NoiseSymmetricState
	LocalStatic   *X25519Keys
	LocalEphemeral *X25519Keys
	RemoteStatic  []byte
	RemoteEphemeral []byte
}

// NewNoiseHandshake creates a new handshake with the given static keys.
func NewNoiseHandshake(localStatic *X25519Keys) (*NoiseHandshake, error) {
	ephemeral, err := GenerateX25519Keys()
	if err != nil {
		return nil, err
	}

	return &NoiseHandshake{
		State:          &NoiseSymmetricState{},
		LocalStatic:    localStatic,
		LocalEphemeral: ephemeral,
	}, nil
}

// InitiatorInit initializes as the initiator (Alice) for Noise_XK.
// remoteStaticKey is Bob's known static public key.
func (h *NoiseHandshake) InitiatorInit(remoteStaticKey []byte, isSSU2 bool) {
	h.RemoteStatic = make([]byte, 32)
	copy(h.RemoteStatic, remoteStaticKey)

	if isSSU2 {
		h.State.InitSSU2(remoteStaticKey)
	} else {
		h.State.InitNTCP2(remoteStaticKey)
	}
}

// ResponderInit initializes as the responder (Bob) for Noise_XK.
func (h *NoiseHandshake) ResponderInit(isSSU2 bool) {
	// For responder, we don't know the initiator's static key yet
	// We use our own static key for the initial hash
	if isSSU2 {
		h.State.InitSSU2(h.LocalStatic.PublicKey())
	} else {
		h.State.InitNTCP2(h.LocalStatic.PublicKey())
	}
}

// MixDH performs a Diffie-Hellman operation and mixes the result into the key.
func (h *NoiseHandshake) MixDH(localKey *X25519Keys, remoteKey []byte) error {
	shared, err := localKey.SharedSecret(remoteKey)
	if err != nil {
		return err
	}
	return h.State.MixKey(shared)
}
