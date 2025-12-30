// Package i2np implements the I2P Network Protocol messages.
package i2np

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/go-i2p/go-i2p/pkg/crypto"
)

// I2NP Header sizes
const (
	I2NPHeaderSize      = 16 // Full header: type(1) + msgID(4) + expiration(8) + size(2) + checksum(1)
	I2NPShortHeaderSize = 5  // Short header: type(1) + expiration(4)
	I2NPNTCP2HeaderSize = 13 // NTCP2 header: type(1) + msgID(4) + expiration(4) + size(2) + reserved(2)
)

// I2NP Header offsets
const (
	HeaderTypeIDOffset     = 0
	HeaderMsgIDOffset      = 1
	HeaderExpirationOffset = 5
	HeaderSizeOffset       = 13
	HeaderChecksumOffset   = 15
)

// I2NP Message size limits
const (
	MaxMessageSize       = 62708
	MaxShortMessageSize  = 4096
	MaxMediumMessageSize = 16384
)

// Message expiration
const (
	MessageExpirationTimeout = 8000 * time.Millisecond
	MessageClockSkew         = 60 * time.Second
)

// I2NP Message types
type MessageType uint8

const (
	TypeDatabaseStore           MessageType = 1
	TypeDatabaseLookup          MessageType = 2
	TypeDatabaseSearchReply     MessageType = 3
	TypeDeliveryStatus          MessageType = 10
	TypeGarlic                  MessageType = 11
	TypeTunnelData              MessageType = 18
	TypeTunnelGateway           MessageType = 19
	TypeData                    MessageType = 20
	TypeTunnelBuild             MessageType = 21
	TypeTunnelBuildReply        MessageType = 22
	TypeVariableTunnelBuild     MessageType = 23
	TypeVariableTunnelBuildReply MessageType = 24
	TypeShortTunnelBuild        MessageType = 25
	TypeShortTunnelBuildReply   MessageType = 26
)

// String returns the message type name.
func (t MessageType) String() string {
	switch t {
	case TypeDatabaseStore:
		return "DatabaseStore"
	case TypeDatabaseLookup:
		return "DatabaseLookup"
	case TypeDatabaseSearchReply:
		return "DatabaseSearchReply"
	case TypeDeliveryStatus:
		return "DeliveryStatus"
	case TypeGarlic:
		return "Garlic"
	case TypeTunnelData:
		return "TunnelData"
	case TypeTunnelGateway:
		return "TunnelGateway"
	case TypeData:
		return "Data"
	case TypeTunnelBuild:
		return "TunnelBuild"
	case TypeTunnelBuildReply:
		return "TunnelBuildReply"
	case TypeVariableTunnelBuild:
		return "VariableTunnelBuild"
	case TypeVariableTunnelBuildReply:
		return "VariableTunnelBuildReply"
	case TypeShortTunnelBuild:
		return "ShortTunnelBuild"
	case TypeShortTunnelBuildReply:
		return "ShortTunnelBuildReply"
	default:
		return "Unknown"
	}
}

var (
	ErrInvalidMessage    = errors.New("i2np: invalid message")
	ErrMessageTooShort   = errors.New("i2np: message too short")
	ErrMessageTooLarge   = errors.New("i2np: message too large")
	ErrInvalidChecksum   = errors.New("i2np: invalid checksum")
	ErrMessageExpired    = errors.New("i2np: message expired")
	ErrUnknownMessageType = errors.New("i2np: unknown message type")
)

// Message is the interface for all I2NP messages.
type Message interface {
	Type() MessageType
	GetMsgID() uint32
	GetExpiration() time.Time
	ToBytes() []byte
}

// RawMessage represents a raw I2NP message with header.
type RawMessage struct {
	typeID     MessageType
	msgID      uint32
	expiration int64 // milliseconds since epoch
	payload    []byte
}

// NewRawMessage creates a new RawMessage.
func NewRawMessage(typeID MessageType, payload []byte) *RawMessage {
	msgID := generateMsgID()
	expiration := time.Now().Add(MessageExpirationTimeout).UnixMilli()

	return &RawMessage{
		typeID:     typeID,
		msgID:      msgID,
		expiration: expiration,
		payload:    payload,
	}
}

// ParseRawMessage parses a raw I2NP message from bytes.
func ParseRawMessage(data []byte) (*RawMessage, error) {
	if len(data) < I2NPHeaderSize {
		return nil, ErrMessageTooShort
	}

	msg := &RawMessage{
		typeID:     MessageType(data[HeaderTypeIDOffset]),
		msgID:      binary.BigEndian.Uint32(data[HeaderMsgIDOffset:]),
		expiration: int64(binary.BigEndian.Uint64(data[HeaderExpirationOffset:])),
	}

	size := binary.BigEndian.Uint16(data[HeaderSizeOffset:])
	checksum := data[HeaderChecksumOffset]

	if len(data) < I2NPHeaderSize+int(size) {
		return nil, ErrMessageTooShort
	}

	msg.payload = make([]byte, size)
	copy(msg.payload, data[I2NPHeaderSize:I2NPHeaderSize+int(size)])

	// Verify checksum (first byte of SHA256 of payload)
	hash := crypto.SHA256(msg.payload)
	if hash[0] != checksum {
		return nil, ErrInvalidChecksum
	}

	return msg, nil
}

// Type returns the message type.
func (m *RawMessage) Type() MessageType {
	return m.typeID
}

// GetMsgID returns the message ID.
func (m *RawMessage) GetMsgID() uint32 {
	return m.msgID
}

// GetExpiration returns the expiration time.
func (m *RawMessage) GetExpiration() time.Time {
	return time.UnixMilli(m.expiration)
}

// Payload returns the message payload.
func (m *RawMessage) Payload() []byte {
	return m.payload
}

// IsExpired returns true if the message has expired.
func (m *RawMessage) IsExpired() bool {
	return time.Now().UnixMilli() > m.expiration+int64(MessageClockSkew.Milliseconds())
}

// ToBytes serializes the message to bytes with full header.
func (m *RawMessage) ToBytes() []byte {
	size := len(m.payload)
	buf := make([]byte, I2NPHeaderSize+size)

	buf[HeaderTypeIDOffset] = byte(m.typeID)
	binary.BigEndian.PutUint32(buf[HeaderMsgIDOffset:], m.msgID)
	binary.BigEndian.PutUint64(buf[HeaderExpirationOffset:], uint64(m.expiration))
	binary.BigEndian.PutUint16(buf[HeaderSizeOffset:], uint16(size))

	// Checksum is first byte of SHA256(payload)
	hash := crypto.SHA256(m.payload)
	buf[HeaderChecksumOffset] = hash[0]

	copy(buf[I2NPHeaderSize:], m.payload)

	return buf
}

// ToShortBytes serializes the message with short header (for SSU2).
func (m *RawMessage) ToShortBytes() []byte {
	size := len(m.payload)
	buf := make([]byte, I2NPShortHeaderSize+size)

	buf[0] = byte(m.typeID)
	binary.BigEndian.PutUint32(buf[1:], uint32(m.expiration/1000)) // Seconds

	copy(buf[I2NPShortHeaderSize:], m.payload)

	return buf
}

// ToNTCP2Bytes serializes the message with NTCP2 header.
func (m *RawMessage) ToNTCP2Bytes() []byte {
	size := len(m.payload)
	buf := make([]byte, I2NPNTCP2HeaderSize+size)

	buf[0] = byte(m.typeID)
	binary.BigEndian.PutUint32(buf[1:], m.msgID)
	binary.BigEndian.PutUint32(buf[5:], uint32(m.expiration/1000)) // Seconds

	copy(buf[I2NPNTCP2HeaderSize:], m.payload)

	return buf
}

// ParseFromShort parses a message from short header format.
func ParseFromShort(data []byte, msgID uint32) (*RawMessage, error) {
	if len(data) < I2NPShortHeaderSize {
		return nil, ErrMessageTooShort
	}

	msg := &RawMessage{
		typeID:     MessageType(data[0]),
		msgID:      msgID,
		expiration: int64(binary.BigEndian.Uint32(data[1:])) * 1000, // Seconds to milliseconds
	}

	msg.payload = make([]byte, len(data)-I2NPShortHeaderSize)
	copy(msg.payload, data[I2NPShortHeaderSize:])

	return msg, nil
}

// ParseFromNTCP2 parses a message from NTCP2 header format.
func ParseFromNTCP2(data []byte) (*RawMessage, error) {
	if len(data) < I2NPNTCP2HeaderSize {
		return nil, ErrMessageTooShort
	}

	msg := &RawMessage{
		typeID:     MessageType(data[0]),
		msgID:      binary.BigEndian.Uint32(data[1:]),
		expiration: int64(binary.BigEndian.Uint32(data[5:])) * 1000, // Seconds to milliseconds
	}

	msg.payload = make([]byte, len(data)-I2NPNTCP2HeaderSize)
	copy(msg.payload, data[I2NPNTCP2HeaderSize:])

	return msg, nil
}

// generateMsgID generates a random 32-bit message ID.
func generateMsgID() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

// GenerateMsgID generates a random message ID (exported).
func GenerateMsgID() uint32 {
	return generateMsgID()
}

// ParseMessage parses an I2NP message from a RawMessage payload.
func ParseMessage(raw *RawMessage) (Message, error) {
	payload := raw.Payload()

	switch raw.Type() {
	case TypeDatabaseStore:
		return ParseDatabaseStore(payload)
	case TypeDatabaseLookup:
		return ParseDatabaseLookup(payload)
	case TypeDatabaseSearchReply:
		return ParseDatabaseSearchReply(payload)
	case TypeDeliveryStatus:
		return ParseDeliveryStatus(payload)
	case TypeGarlic:
		return ParseGarlic(payload)
	case TypeTunnelData:
		return ParseTunnelData(payload)
	case TypeTunnelGateway:
		return ParseTunnelGateway(payload)
	case TypeData:
		return ParseData(payload)
	case TypeTunnelBuild:
		return ParseTunnelBuild(payload)
	case TypeTunnelBuildReply:
		return ParseTunnelBuildReply(payload)
	case TypeVariableTunnelBuild:
		return ParseVariableTunnelBuild(payload)
	case TypeVariableTunnelBuildReply:
		return ParseVariableTunnelBuildReply(payload)
	case TypeShortTunnelBuild:
		return ParseShortTunnelBuild(payload)
	case TypeShortTunnelBuildReply:
		return ParseShortTunnelBuildReply(payload)
	default:
		return nil, ErrUnknownMessageType
	}
}
