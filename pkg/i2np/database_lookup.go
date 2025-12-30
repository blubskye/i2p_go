package i2np

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// DatabaseLookup flags
const (
	DatabaseLookupDeliveryFlag   = 0x01 // Reply through tunnel
	DatabaseLookupEncryptionFlag = 0x02 // Encrypt reply
	DatabaseLookupECIESFlag      = 0x10 // Use ECIES encryption

	// Lookup type (bits 2-3)
	DatabaseLookupTypeNormal      = 0x00
	DatabaseLookupTypeLeaseSet    = 0x04
	DatabaseLookupTypeRouterInfo  = 0x08
	DatabaseLookupTypeExploratory = 0x0C
)

// DatabaseLookup requests data from the network database.
type DatabaseLookup struct {
	Key           data.Hash
	From          data.Hash // Reply to this router or tunnel gateway
	Flags         uint8
	ReplyTunnelID uint32   // If DeliveryFlag set
	ExcludePeers  []data.Hash
	ReplyKey      []byte   // For encrypted replies (32 bytes)
	Tags          [][]byte // Session tags for encrypted replies
}

// NewDatabaseLookup creates a new DatabaseLookup message.
func NewDatabaseLookup(key, from data.Hash, lookupType uint8) *DatabaseLookup {
	return &DatabaseLookup{
		Key:   key,
		From:  from,
		Flags: lookupType,
	}
}

// NewDatabaseLookupTunnel creates a lookup with tunnel reply.
func NewDatabaseLookupTunnel(key, gateway data.Hash, tunnelID uint32, lookupType uint8) *DatabaseLookup {
	return &DatabaseLookup{
		Key:           key,
		From:          gateway,
		Flags:         lookupType | DatabaseLookupDeliveryFlag,
		ReplyTunnelID: tunnelID,
	}
}

// ParseDatabaseLookup parses a DatabaseLookup from payload bytes.
func ParseDatabaseLookup(payload []byte) (*DatabaseLookup, error) {
	if len(payload) < 65 { // Key (32) + From (32) + Flags (1)
		return nil, ErrMessageTooShort
	}

	dl := &DatabaseLookup{}
	offset := 0

	copy(dl.Key[:], payload[offset:offset+32])
	offset += 32
	copy(dl.From[:], payload[offset:offset+32])
	offset += 32
	dl.Flags = payload[offset]
	offset++

	// If tunnel delivery flag is set, read tunnel ID
	if dl.Flags&DatabaseLookupDeliveryFlag != 0 {
		if len(payload) < offset+4 {
			return nil, ErrMessageTooShort
		}
		dl.ReplyTunnelID = binary.BigEndian.Uint32(payload[offset:])
		offset += 4
	}

	// Read exclude peer count
	if len(payload) < offset+2 {
		return nil, ErrMessageTooShort
	}
	excludeCount := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2

	// Read excluded peers
	dl.ExcludePeers = make([]data.Hash, 0, excludeCount)
	for i := 0; i < excludeCount; i++ {
		if len(payload) < offset+32 {
			return nil, ErrMessageTooShort
		}
		var h data.Hash
		copy(h[:], payload[offset:offset+32])
		dl.ExcludePeers = append(dl.ExcludePeers, h)
		offset += 32
	}

	// If encryption flag is set, read reply key and tags
	if dl.Flags&DatabaseLookupEncryptionFlag != 0 {
		if len(payload) < offset+33 { // Key (32) + tag count (1)
			return nil, ErrMessageTooShort
		}
		dl.ReplyKey = make([]byte, 32)
		copy(dl.ReplyKey, payload[offset:offset+32])
		offset += 32

		tagCount := int(payload[offset])
		offset++

		dl.Tags = make([][]byte, 0, tagCount)
		for i := 0; i < tagCount; i++ {
			if len(payload) < offset+32 {
				return nil, ErrMessageTooShort
			}
			tag := make([]byte, 32)
			copy(tag, payload[offset:offset+32])
			dl.Tags = append(dl.Tags, tag)
			offset += 32
		}
	}

	return dl, nil
}

// Type returns TypeDatabaseLookup.
func (d *DatabaseLookup) Type() MessageType {
	return TypeDatabaseLookup
}

// GetMsgID returns 0 (use RawMessage for actual ID).
func (d *DatabaseLookup) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time (use RawMessage for actual expiration).
func (d *DatabaseLookup) GetExpiration() time.Time {
	return time.Now()
}

// GetLookupType returns the lookup type from flags.
func (d *DatabaseLookup) GetLookupType() uint8 {
	return d.Flags & 0x0C
}

// IsExploratoryLookup returns true if this is an exploratory lookup.
func (d *DatabaseLookup) IsExploratoryLookup() bool {
	return d.GetLookupType() == DatabaseLookupTypeExploratory
}

// IsLeaseSetLookup returns true if this is a LeaseSet lookup.
func (d *DatabaseLookup) IsLeaseSetLookup() bool {
	return d.GetLookupType() == DatabaseLookupTypeLeaseSet
}

// IsRouterInfoLookup returns true if this is a RouterInfo lookup.
func (d *DatabaseLookup) IsRouterInfoLookup() bool {
	return d.GetLookupType() == DatabaseLookupTypeRouterInfo
}

// IsTunnelDelivery returns true if reply should go through tunnel.
func (d *DatabaseLookup) IsTunnelDelivery() bool {
	return d.Flags&DatabaseLookupDeliveryFlag != 0
}

// IsEncrypted returns true if reply should be encrypted.
func (d *DatabaseLookup) IsEncrypted() bool {
	return d.Flags&DatabaseLookupEncryptionFlag != 0
}

// ToPayload serializes the DatabaseLookup to payload bytes.
func (d *DatabaseLookup) ToPayload() []byte {
	size := 32 + 32 + 1 + 2 // Key + From + Flags + ExcludeCount
	if d.Flags&DatabaseLookupDeliveryFlag != 0 {
		size += 4 // TunnelID
	}
	size += len(d.ExcludePeers) * 32
	if d.Flags&DatabaseLookupEncryptionFlag != 0 {
		size += 32 + 1 + len(d.Tags)*32 // ReplyKey + TagCount + Tags
	}

	buf := make([]byte, size)
	offset := 0

	copy(buf[offset:], d.Key[:])
	offset += 32
	copy(buf[offset:], d.From[:])
	offset += 32
	buf[offset] = d.Flags
	offset++

	if d.Flags&DatabaseLookupDeliveryFlag != 0 {
		binary.BigEndian.PutUint32(buf[offset:], d.ReplyTunnelID)
		offset += 4
	}

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(d.ExcludePeers)))
	offset += 2

	for _, peer := range d.ExcludePeers {
		copy(buf[offset:], peer[:])
		offset += 32
	}

	if d.Flags&DatabaseLookupEncryptionFlag != 0 {
		copy(buf[offset:], d.ReplyKey)
		offset += 32
		buf[offset] = byte(len(d.Tags))
		offset++
		for _, tag := range d.Tags {
			copy(buf[offset:], tag)
			offset += 32
		}
	}

	return buf
}

// ToBytes serializes to a complete I2NP message.
func (d *DatabaseLookup) ToBytes() []byte {
	return NewRawMessage(TypeDatabaseLookup, d.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (d *DatabaseLookup) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeDatabaseLookup, d.ToPayload())
}
