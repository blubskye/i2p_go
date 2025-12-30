package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

// Build record sizes
const (
	StandardBuildRecordSize = 528  // 16 + 512
	ShortBuildRecordSize    = 218  // 16 + 202
)

// Builder creates tunnels.
type Builder struct {
	localIdentity   data.Hash
	onSendMessage   func(dest data.Hash, msg *i2np.RawMessage) error
	pendingBuilds   map[uint32]*PendingBuild
}

// PendingBuild represents a tunnel build in progress.
type PendingBuild struct {
	Config      *TunnelConfig
	ReplyKeys   [][32]byte
	ReplyIVs    [][16]byte
	MsgID       uint32
	StartTime   time.Time
	OnComplete  func(Tunnel, error)
}

// NewBuilder creates a new tunnel builder.
func NewBuilder(localIdentity data.Hash) *Builder {
	return &Builder{
		localIdentity: localIdentity,
		pendingBuilds: make(map[uint32]*PendingBuild),
	}
}

// SetMessageSender sets the function to send I2NP messages.
func (b *Builder) SetMessageSender(sender func(dest data.Hash, msg *i2np.RawMessage) error) {
	b.onSendMessage = sender
}

// BuildTunnel builds a tunnel with the given hops.
func (b *Builder) BuildTunnel(tunnelType TunnelType, hops []data.Hash, onComplete func(Tunnel, error)) error {
	if len(hops) == 0 || len(hops) > MaxTunnelHops {
		return ErrTunnelBuildFailed
	}

	// Generate tunnel configuration
	config, err := b.generateConfig(tunnelType, hops)
	if err != nil {
		return err
	}

	// Generate message ID
	var msgID uint32
	msgIDBytes := make([]byte, 4)
	rand.Read(msgIDBytes)
	msgID = binary.BigEndian.Uint32(msgIDBytes)

	// Store reply keys for decrypting responses
	replyKeys := make([][32]byte, len(config.Hops))
	replyIVs := make([][16]byte, len(config.Hops))
	for i, hop := range config.Hops {
		replyKeys[i] = hop.ReplyKey
		replyIVs[i] = hop.ReplyIV
	}

	// Create pending build
	pending := &PendingBuild{
		Config:     config,
		ReplyKeys:  replyKeys,
		ReplyIVs:   replyIVs,
		MsgID:      msgID,
		StartTime:  time.Now(),
		OnComplete: onComplete,
	}
	b.pendingBuilds[msgID] = pending

	// Create build request records
	records, err := b.createBuildRecords(config, msgID)
	if err != nil {
		delete(b.pendingBuilds, msgID)
		return err
	}

	// Create and send VariableTunnelBuild message
	buildMsg := i2np.NewVariableTunnelBuild(records)

	if b.onSendMessage != nil {
		// Send to first hop
		err = b.onSendMessage(config.Hops[0].RouterHash, buildMsg.ToRawMessage())
		if err != nil {
			delete(b.pendingBuilds, msgID)
			return err
		}
	}

	// Start timeout timer
	go func() {
		time.Sleep(TunnelBuildTimeout)
		b.handleTimeout(msgID)
	}()

	return nil
}

// generateConfig generates a complete tunnel configuration.
func (b *Builder) generateConfig(tunnelType TunnelType, hops []data.Hash) (*TunnelConfig, error) {
	config := &TunnelConfig{
		Type: tunnelType,
		Hops: make([]*HopConfig, len(hops)),
	}

	for i := range hops {
		hop := &HopConfig{
			RouterHash: hops[i],
			IsGateway:  i == 0,
			IsEndpoint: i == len(hops)-1,
		}

		// Generate random tunnel IDs
		idBytes := make([]byte, 4)
		rand.Read(idBytes)
		hop.TunnelID = TunnelID(binary.BigEndian.Uint32(idBytes))

		if i < len(hops)-1 {
			rand.Read(idBytes)
			hop.NextTunnelID = TunnelID(binary.BigEndian.Uint32(idBytes))
			hop.NextRouter = hops[i+1]
		}

		// Generate random keys
		keyBytes := make([]byte, 32)
		rand.Read(keyBytes)
		copy(hop.LayerKey[:], keyBytes)

		rand.Read(keyBytes)
		copy(hop.IVKey[:], keyBytes)

		rand.Read(keyBytes)
		copy(hop.ReplyKey[:], keyBytes)

		ivBytes := make([]byte, 16)
		rand.Read(ivBytes)
		copy(hop.ReplyIV[:], ivBytes)

		config.Hops[i] = hop
	}

	// Set tunnel IDs based on type
	if tunnelType == TunnelTypeInbound {
		// For inbound: we receive at the last hop's tunnel ID
		config.ReceiveTunnelID = config.Hops[len(hops)-1].TunnelID
		config.Gateway = config.Hops[0].RouterHash
	} else {
		// For outbound: we send to the first hop's tunnel ID
		config.SendTunnelID = config.Hops[0].TunnelID
		config.Endpoint = config.Hops[len(hops)-1].RouterHash
	}

	return config, nil
}

// createBuildRecords creates the encrypted build request records.
func (b *Builder) createBuildRecords(config *TunnelConfig, msgID uint32) ([]*i2np.TunnelBuildRecord, error) {
	records := make([]*i2np.TunnelBuildRecord, len(config.Hops))

	for i, hop := range config.Hops {
		record := &i2np.TunnelBuildRecord{}

		// Copy ToPeer (router hash)
		copy(record.ToPeer[:], hop.RouterHash[:])

		// Create plaintext record content
		plaintext := make([]byte, StandardBuildRecordSize-16) // 512 bytes

		offset := 0

		// Tunnel ID (4 bytes)
		binary.BigEndian.PutUint32(plaintext[offset:], uint32(hop.TunnelID))
		offset += 4

		// Next Tunnel ID (4 bytes)
		binary.BigEndian.PutUint32(plaintext[offset:], uint32(hop.NextTunnelID))
		offset += 4

		// Next Router Hash (32 bytes)
		copy(plaintext[offset:], hop.NextRouter[:])
		offset += 32

		// Layer Key (32 bytes)
		copy(plaintext[offset:], hop.LayerKey[:])
		offset += 32

		// IV Key (32 bytes)
		copy(plaintext[offset:], hop.IVKey[:])
		offset += 32

		// Reply Key (32 bytes)
		copy(plaintext[offset:], hop.ReplyKey[:])
		offset += 32

		// Reply IV (16 bytes)
		copy(plaintext[offset:], hop.ReplyIV[:])
		offset += 16

		// Flags (1 byte)
		var flags uint8
		if hop.IsGateway {
			flags |= 0x80
		}
		if hop.IsEndpoint {
			flags |= 0x40
		}
		plaintext[offset] = flags
		offset++

		// Request time (4 bytes)
		binary.BigEndian.PutUint32(plaintext[offset:], uint32(time.Now().Unix()/1000))
		offset += 4

		// Send message ID (4 bytes)
		binary.BigEndian.PutUint32(plaintext[offset:], msgID)
		offset += 4

		// Random padding for rest
		rand.Read(plaintext[offset:])

		// Encrypt the record (in real implementation, this would use
		// ElGamal+AES for standard builds or ECIES for short builds)
		// For now, we'll just copy the plaintext as placeholder
		record.EncryptedData = make([]byte, StandardBuildRecordSize-16)
		copy(record.EncryptedData, plaintext)

		records[i] = record
	}

	return records, nil
}

// HandleBuildReply processes a tunnel build reply.
func (b *Builder) HandleBuildReply(replyMsg *i2np.VariableTunnelBuildReply) error {
	// Decrypt records to find our build
	// This is simplified - real implementation needs to track by reply encryption

	for msgID, pending := range b.pendingBuilds {
		// Try to decrypt with this pending build's keys
		success := b.tryDecryptReply(pending, replyMsg.Records)
		if success {
			delete(b.pendingBuilds, msgID)

			// Create the tunnel
			var tunnel Tunnel
			if pending.Config.Type == TunnelTypeInbound {
				tunnel = NewInboundTunnel(pending.Config)
				tunnel.(*InboundTunnel).SetEstablished()
			} else {
				tunnel = NewOutboundTunnel(pending.Config)
				tunnel.(*OutboundTunnel).SetEstablished()
			}

			if pending.OnComplete != nil {
				pending.OnComplete(tunnel, nil)
			}
			return nil
		}
	}

	return ErrTunnelBuildFailed
}

// tryDecryptReply attempts to decrypt a build reply with pending keys.
func (b *Builder) tryDecryptReply(pending *PendingBuild, records []*i2np.TunnelBuildReplyRecord) bool {
	if len(records) != len(pending.Config.Hops) {
		return false
	}

	// Decrypt each record and check for acceptance
	for i, record := range records {
		// Decrypt with reply key and IV
		decrypted, err := crypto.AESDecryptCBC(
			pending.ReplyKeys[i][:],
			pending.ReplyIVs[i][:],
			record.EncryptedData,
		)
		if err != nil {
			return false
		}

		// Check reply byte (first byte after decryption)
		if len(decrypted) > 0 && decrypted[0] != TunnelBuildReplyAccepted {
			return false
		}
	}

	return true
}

// handleTimeout handles a build timeout.
func (b *Builder) handleTimeout(msgID uint32) {
	pending, ok := b.pendingBuilds[msgID]
	if !ok {
		return // Already completed
	}

	delete(b.pendingBuilds, msgID)

	if pending.OnComplete != nil {
		pending.OnComplete(nil, ErrTunnelBuildTimeout)
	}
}

// CreateTransitTunnel creates a transit tunnel from a build request record.
func CreateTransitTunnel(record *TunnelBuildRecord, recordData []byte) (*TransitTunnel, error) {
	// Parse the decrypted record data
	if len(recordData) < 156 {
		return nil, ErrInvalidTunnelData
	}

	offset := 0

	tunnelID := TunnelID(binary.BigEndian.Uint32(recordData[offset:]))
	offset += 4

	nextTunnelID := TunnelID(binary.BigEndian.Uint32(recordData[offset:]))
	offset += 4

	var nextRouter data.Hash
	copy(nextRouter[:], recordData[offset:offset+32])
	offset += 32

	var layerKey [32]byte
	copy(layerKey[:], recordData[offset:offset+32])
	offset += 32

	var ivKey [32]byte
	copy(ivKey[:], recordData[offset:offset+32])
	offset += 32

	// Skip reply key and IV (we don't need them for transit)
	offset += 48

	flags := recordData[offset]
	isGateway := (flags & 0x80) != 0
	isEndpoint := (flags & 0x40) != 0

	return NewTransitTunnel(
		tunnelID,
		nextTunnelID,
		nextRouter,
		layerKey,
		ivKey,
		isGateway,
		isEndpoint,
	), nil
}
