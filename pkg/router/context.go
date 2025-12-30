package router

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
)

// Context holds the router's identity and keys.
type Context struct {
	// Router identity
	identity    *data.IdentityEx
	privateKeys *data.PrivateKeys
	identHash   data.Hash

	// NTCP2 static keys (separate from identity encryption keys)
	ntcp2Keys *crypto.X25519Keys

	// RouterInfo
	routerInfo        *data.RouterInfo
	routerInfoUpdated time.Time

	// Data directory
	dataDir string
}

// NewContext creates a new router context.
func NewContext(config *Config) (*Context, error) {
	ctx := &Context{
		dataDir: config.DataDir,
	}

	// Ensure data directory exists
	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, err
	}

	// Load or create identity
	identPath := filepath.Join(config.DataDir, config.IdentityPath)
	if err := ctx.loadOrCreateIdentity(identPath); err != nil {
		return nil, err
	}

	// Generate NTCP2 keys
	ntcp2Keys, err := crypto.GenerateX25519Keys()
	if err != nil {
		return nil, err
	}
	ctx.ntcp2Keys = ntcp2Keys

	return ctx, nil
}

// loadOrCreateIdentity loads or creates the router identity.
func (c *Context) loadOrCreateIdentity(path string) error {
	// Try to load existing identity
	if _, err := os.Stat(path); err == nil {
		return c.loadIdentity(path)
	}

	// Create new identity
	return c.createIdentity(path)
}

// loadIdentity loads an identity from a file.
func (c *Context) loadIdentity(path string) error {
	identData, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Parse identity
	identity, err := data.NewIdentityEx(identData)
	if err != nil {
		return err
	}

	c.identity = identity
	c.identHash = identity.GetIdentHash()

	// Load private keys from remaining data
	identLen := identity.FullLen()
	if len(identData) > identLen {
		keyData := identData[identLen:]
		c.loadPrivateKeys(identity, keyData)
	}

	return nil
}

// createIdentity creates a new router identity.
func (c *Context) createIdentity(path string) error {
	// Generate Ed25519 signing keys
	signingKeys, err := crypto.GenerateEd25519Keys()
	if err != nil {
		return err
	}

	// Generate X25519 encryption keys
	encryptKeys, err := crypto.GenerateX25519Keys()
	if err != nil {
		return err
	}

	// Build the identity
	identity := &data.IdentityEx{}

	// Set up standard identity with ElGamal-size padding
	// and the actual key in the appropriate position
	copy(identity.StandardIdentity.PublicKey[256-32:], encryptKeys.PublicKey()[:])
	copy(identity.StandardIdentity.SigningKey[128-32:], signingKeys.PublicKey()[:])

	// Set up key certificate for Ed25519 + X25519
	identity.ExtendedBuffer = make([]byte, 4)
	// Signing type: EdDSA_SHA512_Ed25519 (7)
	identity.ExtendedBuffer[0] = 0x00
	identity.ExtendedBuffer[1] = 0x07
	// Crypto type: ECIES_X25519_AEAD (4)
	identity.ExtendedBuffer[2] = 0x00
	identity.ExtendedBuffer[3] = 0x04

	// Update certificate to indicate key certificate
	identity.StandardIdentity.Certificate[0] = data.CertificateTypeKey
	identity.StandardIdentity.Certificate[1] = 0x00
	identity.StandardIdentity.Certificate[2] = 0x04 // 4 bytes

	c.identity = identity
	c.identHash = identity.GetIdentHash()

	// Create private keys
	c.privateKeys = &data.PrivateKeys{
		Identity:          identity,
		EncryptionPrivKey: encryptKeys.PrivateKey(),
		SigningPrivKey:    signingKeys.PrivateKey(),
	}

	// Save to file
	return c.saveIdentity(path)
}

// loadPrivateKeys loads private keys from data.
func (c *Context) loadPrivateKeys(identity *data.IdentityEx, keyData []byte) {
	// Private key layout depends on key types
	// For Ed25519 + X25519: 32 bytes signing + 32 bytes encryption
	if len(keyData) >= 64 {
		c.privateKeys = &data.PrivateKeys{
			Identity:          identity,
			SigningPrivKey:    keyData[:32],
			EncryptionPrivKey: keyData[32:64],
		}
	}
}

// saveIdentity saves the identity to a file.
func (c *Context) saveIdentity(path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Build file content: IdentityEx + PrivateKeys
	identData := c.identity.ToBuffer()

	// Append private keys
	if c.privateKeys != nil {
		identData = append(identData, c.privateKeys.SigningPrivKey...)
		identData = append(identData, c.privateKeys.EncryptionPrivKey...)
	}

	return os.WriteFile(path, identData, 0600)
}

// Identity returns the router identity.
func (c *Context) Identity() *data.IdentityEx {
	return c.identity
}

// IdentHash returns the router identity hash.
func (c *Context) IdentHash() data.Hash {
	return c.identHash
}

// PrivateKeys returns the private keys.
func (c *Context) PrivateKeys() *data.PrivateKeys {
	return c.privateKeys
}

// EncryptionKeys returns X25519 keys for encryption (placeholder).
func (c *Context) EncryptionKeys() *crypto.X25519Keys {
	// Would reconstruct from private key material
	return c.ntcp2Keys
}

// NTCP2Keys returns the NTCP2 static keys.
func (c *Context) NTCP2Keys() *crypto.X25519Keys {
	return c.ntcp2Keys
}

// RouterInfo returns the current RouterInfo.
func (c *Context) RouterInfo() *data.RouterInfo {
	return c.routerInfo
}

// UpdateRouterInfo updates the RouterInfo.
func (c *Context) UpdateRouterInfo(ri *data.RouterInfo) {
	c.routerInfo = ri
	c.routerInfoUpdated = time.Now()
}

// BuildRouterInfo creates a new RouterInfo for publishing.
func (c *Context) BuildRouterInfo(ntcp2Addr, ssu2Addr string, caps data.Caps) *data.RouterInfo {
	ri := &data.RouterInfo{}

	// Set identity
	ri.Identity = c.identity

	// Set timestamp
	ri.Timestamp = time.Now().UnixMilli()

	// Add NTCP2 address
	if ntcp2Addr != "" {
		var staticKey [32]byte
		copy(staticKey[:], c.ntcp2Keys.PublicKey()[:])
		ri.Addresses = append(ri.Addresses, &data.RouterAddress{
			TransportStyle: data.TransportNTCP2,
			Cost:           10,
			StaticKey:      staticKey,
			Version:        2,
		})
	}

	// Add SSU2 address
	if ssu2Addr != "" {
		var staticKey [32]byte
		copy(staticKey[:], c.ntcp2Keys.PublicKey()[:])
		ri.Addresses = append(ri.Addresses, &data.RouterAddress{
			TransportStyle: data.TransportSSU2,
			Cost:           15,
			StaticKey:      staticKey,
		})
	}

	// Set properties (includes caps)
	ri.Properties = make(map[string]string)
	ri.Properties["caps"] = string(caps)
	ri.Properties["router.version"] = "0.9.62"

	// Sign the RouterInfo
	c.signRouterInfo(ri)

	c.routerInfo = ri
	c.routerInfoUpdated = time.Now()

	return ri
}

// signRouterInfo signs the RouterInfo.
func (c *Context) signRouterInfo(ri *data.RouterInfo) {
	if c.privateKeys == nil {
		return
	}

	// Get the data to sign (the serialized RouterInfo without signature)
	// For now, use ToBuffer and strip the signature
	dataToSign := ri.ToBuffer()
	if len(dataToSign) > 64 {
		// Remove trailing signature (Ed25519 is 64 bytes)
		dataToSign = dataToSign[:len(dataToSign)-64]
	}

	// Sign with our signing key
	sig, err := c.privateKeys.Sign(dataToSign)
	if err == nil {
		ri.Signature = sig
	}
}

// GenerateNonce generates a random nonce.
func (c *Context) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}

// DataDir returns the data directory path.
func (c *Context) DataDir() string {
	return c.dataDir
}
