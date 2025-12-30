package i2np

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// DatabaseStore type values
const (
	DatabaseStoreTypeRouterInfo = 0
	DatabaseStoreTypeLeaseSet   = 1
	DatabaseStoreTypeLeaseSet2  = 3
)

// DatabaseStore header size
const DatabaseStoreHeaderSize = 37 // Key (32) + Type (1) + ReplyToken (4)

// DatabaseStore stores a RouterInfo or LeaseSet in the network database.
type DatabaseStore struct {
	Key           data.Hash
	StoreType     uint8
	ReplyToken    uint32
	ReplyTunnelID uint32
	ReplyGateway  data.Hash
	Data          []byte // RouterInfo or LeaseSet data
}

// NewDatabaseStore creates a new DatabaseStore message.
func NewDatabaseStore(key data.Hash, storeType uint8, content []byte) *DatabaseStore {
	return &DatabaseStore{
		Key:        key,
		StoreType:  storeType,
		ReplyToken: 0, // No reply requested
		Data:       content,
	}
}

// NewDatabaseStoreWithReply creates a DatabaseStore requesting a reply.
func NewDatabaseStoreWithReply(key data.Hash, storeType uint8, content []byte, replyToken uint32, replyTunnelID uint32, replyGateway data.Hash) *DatabaseStore {
	return &DatabaseStore{
		Key:           key,
		StoreType:     storeType,
		ReplyToken:    replyToken,
		ReplyTunnelID: replyTunnelID,
		ReplyGateway:  replyGateway,
		Data:          content,
	}
}

// ParseDatabaseStore parses a DatabaseStore from payload bytes.
func ParseDatabaseStore(payload []byte) (*DatabaseStore, error) {
	if len(payload) < DatabaseStoreHeaderSize {
		return nil, ErrMessageTooShort
	}

	ds := &DatabaseStore{}
	copy(ds.Key[:], payload[0:32])
	ds.StoreType = payload[32]
	ds.ReplyToken = binary.BigEndian.Uint32(payload[33:37])

	offset := 37
	if ds.ReplyToken != 0 {
		// Reply requested - read tunnel ID and gateway
		if len(payload) < offset+36 {
			return nil, ErrMessageTooShort
		}
		ds.ReplyTunnelID = binary.BigEndian.Uint32(payload[offset:])
		offset += 4
		copy(ds.ReplyGateway[:], payload[offset:offset+32])
		offset += 32
	}

	// Rest is the data
	ds.Data = make([]byte, len(payload)-offset)
	copy(ds.Data, payload[offset:])

	return ds, nil
}

// Type returns TypeDatabaseStore.
func (d *DatabaseStore) Type() MessageType {
	return TypeDatabaseStore
}

// GetMsgID returns 0 (use RawMessage for actual ID).
func (d *DatabaseStore) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time (use RawMessage for actual expiration).
func (d *DatabaseStore) GetExpiration() time.Time {
	return time.Now()
}

// IsRouterInfo returns true if this stores a RouterInfo.
func (d *DatabaseStore) IsRouterInfo() bool {
	return d.StoreType == DatabaseStoreTypeRouterInfo
}

// IsLeaseSet returns true if this stores a LeaseSet.
func (d *DatabaseStore) IsLeaseSet() bool {
	return d.StoreType == DatabaseStoreTypeLeaseSet || d.StoreType == DatabaseStoreTypeLeaseSet2
}

// ToPayload serializes the DatabaseStore to payload bytes.
func (d *DatabaseStore) ToPayload() []byte {
	size := DatabaseStoreHeaderSize
	if d.ReplyToken != 0 {
		size += 36 // TunnelID (4) + Gateway (32)
	}
	size += len(d.Data)

	buf := make([]byte, size)
	offset := 0

	copy(buf[offset:], d.Key[:])
	offset += 32
	buf[offset] = d.StoreType
	offset++
	binary.BigEndian.PutUint32(buf[offset:], d.ReplyToken)
	offset += 4

	if d.ReplyToken != 0 {
		binary.BigEndian.PutUint32(buf[offset:], d.ReplyTunnelID)
		offset += 4
		copy(buf[offset:], d.ReplyGateway[:])
		offset += 32
	}

	copy(buf[offset:], d.Data)

	return buf
}

// ToBytes serializes to a complete I2NP message.
func (d *DatabaseStore) ToBytes() []byte {
	return NewRawMessage(TypeDatabaseStore, d.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (d *DatabaseStore) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeDatabaseStore, d.ToPayload())
}
