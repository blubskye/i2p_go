package tunnel

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
)

// TunnelData represents a 1028-byte tunnel message.
// Format: TunnelID (4 bytes) + IV (16 bytes) + Data (1008 bytes)
type TunnelData struct {
	TunnelID TunnelID
	IV       [16]byte
	Data     [1008]byte
}

// TunnelDataSize constants
const (
	TunnelIVOffset   = 4
	TunnelDataOffset = 20
	TunnelDataLen    = 1008
)

// ParseTunnelData parses a tunnel data message.
func ParseTunnelData(data []byte) (*TunnelData, error) {
	if len(data) < TunnelDataSize {
		return nil, ErrInvalidTunnelData
	}

	td := &TunnelData{
		TunnelID: TunnelID(binary.BigEndian.Uint32(data[0:4])),
	}
	copy(td.IV[:], data[TunnelIVOffset:TunnelIVOffset+16])
	copy(td.Data[:], data[TunnelDataOffset:TunnelDataOffset+TunnelDataLen])

	return td, nil
}

// ToBytes serializes the tunnel data message.
func (td *TunnelData) ToBytes() []byte {
	buf := make([]byte, TunnelDataSize)
	binary.BigEndian.PutUint32(buf[0:4], uint32(td.TunnelID))
	copy(buf[TunnelIVOffset:], td.IV[:])
	copy(buf[TunnelDataOffset:], td.Data[:])
	return buf
}

// EncryptTunnelData encrypts tunnel data for one hop.
// This implements the double-IV encryption scheme used in I2P tunnels.
func EncryptTunnelData(data *TunnelData, layerKey, ivKey [32]byte) (*TunnelData, error) {
	result := &TunnelData{
		TunnelID: data.TunnelID,
	}

	// Step 1: Encrypt the IV using the IV key
	ivCipher, err := aes.NewCipher(ivKey[:])
	if err != nil {
		return nil, err
	}

	// Encrypt IV: IV' = AES-ECB(ivKey, IV)
	ivCipher.Encrypt(result.IV[:], data.IV[:])

	// Step 2: Encrypt the data using the layer key and the original IV
	// Data' = AES-CBC(layerKey, IV, Data)
	encrypted, err := crypto.AESEncryptCBC(layerKey[:], data.IV[:], data.Data[:])
	if err != nil {
		return nil, err
	}
	copy(result.Data[:], encrypted)

	// Step 3: XOR the encrypted IV with first 16 bytes of encrypted data
	for i := 0; i < 16; i++ {
		result.IV[i] ^= result.Data[i]
	}

	return result, nil
}

// DecryptTunnelData decrypts tunnel data for one hop (reverse of encryption).
func DecryptTunnelData(data *TunnelData, layerKey, ivKey [32]byte) (*TunnelData, error) {
	result := &TunnelData{
		TunnelID: data.TunnelID,
	}

	ivCipher, err := aes.NewCipher(ivKey[:])
	if err != nil {
		return nil, err
	}

	// Step 1: XOR to recover the encrypted IV
	var encryptedIV [16]byte
	copy(encryptedIV[:], data.IV[:])
	for i := 0; i < 16; i++ {
		encryptedIV[i] ^= data.Data[i]
	}

	// Step 2: Decrypt the IV
	var decryptedIV [16]byte
	ivCipher.Decrypt(decryptedIV[:], encryptedIV[:])

	// Step 3: Decrypt the data
	decrypted, err := crypto.AESDecryptCBC(layerKey[:], decryptedIV[:], data.Data[:])
	if err != nil {
		return nil, err
	}

	copy(result.IV[:], decryptedIV[:])
	copy(result.Data[:], decrypted)

	return result, nil
}

// EncryptLayered applies layered encryption for an outbound tunnel.
// Encrypts with each hop's key in order (gateway first, endpoint last).
func EncryptLayered(data *TunnelData, keys, ivKeys [][32]byte) (*TunnelData, error) {
	current := data
	var err error

	// Encrypt in order (gateway to endpoint)
	for i := 0; i < len(keys); i++ {
		current, err = EncryptTunnelData(current, keys[i], ivKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return current, nil
}

// DecryptLayered removes layered encryption for an inbound tunnel.
// Decrypts with each hop's key in reverse order (endpoint first, gateway last).
func DecryptLayered(data *TunnelData, keys, ivKeys [][32]byte) (*TunnelData, error) {
	current := data
	var err error

	// Decrypt in reverse order (endpoint to gateway)
	for i := len(keys) - 1; i >= 0; i-- {
		current, err = DecryptTunnelData(current, keys[i], ivKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return current, nil
}

// HandleData processes tunnel data for a transit hop.
func (t *TransitTunnel) HandleData(data []byte) ([]byte, error) {
	td, err := ParseTunnelData(data)
	if err != nil {
		return nil, err
	}

	// Decrypt one layer
	decrypted, err := DecryptTunnelData(td, t.layerKey, t.ivKey)
	if err != nil {
		return nil, err
	}

	// Set the next tunnel ID
	decrypted.TunnelID = t.sendTunnelID

	return decrypted.ToBytes(), nil
}

// HandleData processes tunnel data for an inbound tunnel (at the endpoint).
func (t *InboundTunnel) HandleData(data []byte) ([]byte, error) {
	if t.state != TunnelStateEstablished {
		return nil, ErrTunnelNotReady
	}

	td, err := ParseTunnelData(data)
	if err != nil {
		return nil, err
	}

	// Decrypt all layers
	decrypted, err := DecryptLayered(td, t.keys, t.ivKeys)
	if err != nil {
		return nil, err
	}

	// Return the decrypted payload
	return decrypted.Data[:], nil
}

// HandleData encrypts data for sending through an outbound tunnel.
func (t *OutboundTunnel) HandleData(data []byte) ([]byte, error) {
	if t.state != TunnelStateEstablished {
		return nil, ErrTunnelNotReady
	}

	// Create tunnel data structure
	td := &TunnelData{
		TunnelID: t.tunnelID,
	}

	// Generate random IV
	ivBytes, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	copy(td.IV[:], ivBytes)

	// Copy data (pad if necessary)
	if len(data) > TunnelDataLen {
		data = data[:TunnelDataLen]
	}
	copy(td.Data[:], data)

	// Encrypt all layers
	encrypted, err := EncryptLayered(td, t.keys, t.ivKeys)
	if err != nil {
		return nil, err
	}

	return encrypted.ToBytes(), nil
}

// NextRouter returns the next router for a transit tunnel.
func (t *TransitTunnel) NextRouter() data.Hash {
	return t.nextRouter
}

// SendTunnelID returns the tunnel ID to use when forwarding.
func (t *TransitTunnel) SendTunnelID() TunnelID {
	return t.sendTunnelID
}
