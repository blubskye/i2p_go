package i2np

import (
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// DatabaseSearchReply is sent in response to a DatabaseLookup when the
// requested data is not found. It contains a list of closer peers.
type DatabaseSearchReply struct {
	Key       data.Hash
	PeerHashes []data.Hash
	From      data.Hash
}

// NewDatabaseSearchReply creates a new DatabaseSearchReply message.
func NewDatabaseSearchReply(key, from data.Hash, peers []data.Hash) *DatabaseSearchReply {
	return &DatabaseSearchReply{
		Key:        key,
		PeerHashes: peers,
		From:       from,
	}
}

// ParseDatabaseSearchReply parses a DatabaseSearchReply from payload bytes.
func ParseDatabaseSearchReply(payload []byte) (*DatabaseSearchReply, error) {
	if len(payload) < 33 { // Key (32) + Count (1)
		return nil, ErrMessageTooShort
	}

	dsr := &DatabaseSearchReply{}
	offset := 0

	copy(dsr.Key[:], payload[offset:offset+32])
	offset += 32

	count := int(payload[offset])
	offset++

	// Read peer hashes
	dsr.PeerHashes = make([]data.Hash, 0, count)
	for i := 0; i < count; i++ {
		if len(payload) < offset+32 {
			return nil, ErrMessageTooShort
		}
		var h data.Hash
		copy(h[:], payload[offset:offset+32])
		dsr.PeerHashes = append(dsr.PeerHashes, h)
		offset += 32
	}

	// Read From hash
	if len(payload) < offset+32 {
		return nil, ErrMessageTooShort
	}
	copy(dsr.From[:], payload[offset:offset+32])

	return dsr, nil
}

// Type returns TypeDatabaseSearchReply.
func (d *DatabaseSearchReply) Type() MessageType {
	return TypeDatabaseSearchReply
}

// GetMsgID returns 0 (use RawMessage for actual ID).
func (d *DatabaseSearchReply) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time (use RawMessage for actual expiration).
func (d *DatabaseSearchReply) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the DatabaseSearchReply to payload bytes.
func (d *DatabaseSearchReply) ToPayload() []byte {
	size := 32 + 1 + len(d.PeerHashes)*32 + 32 // Key + Count + Peers + From
	buf := make([]byte, size)
	offset := 0

	copy(buf[offset:], d.Key[:])
	offset += 32

	buf[offset] = byte(len(d.PeerHashes))
	offset++

	for _, peer := range d.PeerHashes {
		copy(buf[offset:], peer[:])
		offset += 32
	}

	copy(buf[offset:], d.From[:])

	return buf
}

// ToBytes serializes to a complete I2NP message.
func (d *DatabaseSearchReply) ToBytes() []byte {
	return NewRawMessage(TypeDatabaseSearchReply, d.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (d *DatabaseSearchReply) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeDatabaseSearchReply, d.ToPayload())
}

// GetPeerCount returns the number of peers in the reply.
func (d *DatabaseSearchReply) GetPeerCount() int {
	return len(d.PeerHashes)
}

// GetPeerByIndex returns the peer hash at the given index.
func (d *DatabaseSearchReply) GetPeerByIndex(index int) (data.Hash, bool) {
	if index < 0 || index >= len(d.PeerHashes) {
		return data.Hash{}, false
	}
	return d.PeerHashes[index], true
}
