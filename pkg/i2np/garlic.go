package i2np

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// GarlicDeliveryType specifies how to deliver a clove.
type GarlicDeliveryType uint8

const (
	GarlicDeliveryTypeLocal       GarlicDeliveryType = 0 // Deliver locally
	GarlicDeliveryTypeDestination GarlicDeliveryType = 1 // Deliver to destination
	GarlicDeliveryTypeRouter      GarlicDeliveryType = 2 // Deliver to router
	GarlicDeliveryTypeTunnel      GarlicDeliveryType = 3 // Deliver to tunnel
)

// Garlic timing constants
const (
	IncomingTagsExpirationTimeout  = 960 // 16 minutes in seconds
	OutgoingTagsExpirationTimeout  = 720 // 12 minutes in seconds
	OutgoingTagsConfirmationTimeout = 10  // 10 seconds
	LeaseSetConfirmationTimeout    = 4000 // in milliseconds
)

// ElGamalBlock contains the encrypted session key for legacy garlic encryption.
type ElGamalBlock struct {
	SessionKey [32]byte
	PreIV      [32]byte
	Padding    [158]byte
}

// GarlicClove represents a single clove in a Garlic message.
type GarlicClove struct {
	DeliveryType       GarlicDeliveryType
	DeliveryInstructions []byte

	// For tunnel delivery
	TunnelID uint32
	Gateway  data.Hash

	// For router/destination delivery
	ToHash data.Hash

	// The enclosed I2NP message
	MsgID      uint32
	Expiration int64  // milliseconds since epoch
	Data       []byte // Enclosed I2NP message data
}

// GarlicCloveDeliveryInstructionsSize returns the size of delivery instructions.
func GarlicCloveDeliveryInstructionsSize(deliveryType GarlicDeliveryType) int {
	switch deliveryType {
	case GarlicDeliveryTypeLocal:
		return 1 // Just the flag byte
	case GarlicDeliveryTypeDestination:
		return 1 + 32 // Flag + Hash
	case GarlicDeliveryTypeRouter:
		return 1 + 32 // Flag + Hash
	case GarlicDeliveryTypeTunnel:
		return 1 + 4 + 32 // Flag + TunnelID + Gateway Hash
	default:
		return 1
	}
}

// ToBytes serializes a GarlicClove.
func (c *GarlicClove) ToBytes() []byte {
	instrSize := GarlicCloveDeliveryInstructionsSize(c.DeliveryType)
	// Clove: DeliveryInstructions + MsgID(4) + Expiration(4) + Size(2) + Data
	size := instrSize + 4 + 4 + 2 + len(c.Data)
	buf := make([]byte, size)
	offset := 0

	// Delivery instructions
	buf[offset] = byte(c.DeliveryType)
	offset++

	switch c.DeliveryType {
	case GarlicDeliveryTypeDestination, GarlicDeliveryTypeRouter:
		copy(buf[offset:], c.ToHash[:])
		offset += 32
	case GarlicDeliveryTypeTunnel:
		binary.BigEndian.PutUint32(buf[offset:], c.TunnelID)
		offset += 4
		copy(buf[offset:], c.Gateway[:])
		offset += 32
	}

	// Message ID
	binary.BigEndian.PutUint32(buf[offset:], c.MsgID)
	offset += 4

	// Expiration (seconds)
	binary.BigEndian.PutUint32(buf[offset:], uint32(c.Expiration/1000))
	offset += 4

	// Size and data
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(c.Data)))
	offset += 2
	copy(buf[offset:], c.Data)

	return buf
}

// ParseGarlicClove parses a single clove from bytes.
func ParseGarlicClove(data []byte) (*GarlicClove, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrMessageTooShort
	}

	clove := &GarlicClove{}
	offset := 0

	// Delivery type is encoded in first byte
	flag := data[offset]
	clove.DeliveryType = GarlicDeliveryType(flag & 0x03)
	offset++

	switch clove.DeliveryType {
	case GarlicDeliveryTypeDestination, GarlicDeliveryTypeRouter:
		if len(data) < offset+32 {
			return nil, 0, ErrMessageTooShort
		}
		copy(clove.ToHash[:], data[offset:offset+32])
		offset += 32
	case GarlicDeliveryTypeTunnel:
		if len(data) < offset+36 {
			return nil, 0, ErrMessageTooShort
		}
		clove.TunnelID = binary.BigEndian.Uint32(data[offset:])
		offset += 4
		copy(clove.Gateway[:], data[offset:offset+32])
		offset += 32
	}

	// Message ID
	if len(data) < offset+4 {
		return nil, 0, ErrMessageTooShort
	}
	clove.MsgID = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Expiration (seconds, convert to milliseconds)
	if len(data) < offset+4 {
		return nil, 0, ErrMessageTooShort
	}
	clove.Expiration = int64(binary.BigEndian.Uint32(data[offset:])) * 1000
	offset += 4

	// Size
	if len(data) < offset+2 {
		return nil, 0, ErrMessageTooShort
	}
	size := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// Data
	if len(data) < offset+size {
		return nil, 0, ErrMessageTooShort
	}
	clove.Data = make([]byte, size)
	copy(clove.Data, data[offset:offset+size])
	offset += size

	return clove, offset, nil
}

// Garlic represents a Garlic message containing encrypted cloves.
type Garlic struct {
	Data []byte // Encrypted garlic data (ElGamal block + AES encrypted cloves)
}

// NewGarlic creates a new Garlic message with pre-encrypted data.
func NewGarlic(encryptedData []byte) *Garlic {
	return &Garlic{
		Data: encryptedData,
	}
}

// ParseGarlic parses a Garlic message from payload bytes.
func ParseGarlic(payload []byte) (*Garlic, error) {
	if len(payload) < 1 {
		return nil, ErrMessageTooShort
	}

	return &Garlic{
		Data: payload,
	}, nil
}

// Type returns TypeGarlic.
func (g *Garlic) Type() MessageType {
	return TypeGarlic
}

// GetMsgID returns 0.
func (g *Garlic) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (g *Garlic) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload returns the encrypted garlic data.
func (g *Garlic) ToPayload() []byte {
	return g.Data
}

// ToBytes serializes to a complete I2NP message.
func (g *Garlic) ToBytes() []byte {
	return NewRawMessage(TypeGarlic, g.ToPayload()).ToBytes()
}

// GarlicPayload represents a decrypted garlic payload with cloves.
type GarlicPayload struct {
	Cloves      []*GarlicClove
	Certificate []byte
	MsgID       uint32
	Expiration  int64
}

// NewGarlicPayload creates a new garlic payload.
func NewGarlicPayload(cloves []*GarlicClove) *GarlicPayload {
	return &GarlicPayload{
		Cloves:     cloves,
		MsgID:      GenerateMsgID(),
		Expiration: time.Now().Add(MessageExpirationTimeout).UnixMilli(),
	}
}

// ToBytes serializes the decrypted garlic payload.
func (p *GarlicPayload) ToBytes() []byte {
	// Calculate size: CloveCount(1) + Cloves + Certificate(3 min) + MsgID(4) + Expiration(4)
	size := 1 + 3 + 4 + 4
	for _, clove := range p.Cloves {
		size += len(clove.ToBytes())
	}

	buf := make([]byte, size)
	offset := 0

	// Number of cloves
	buf[offset] = byte(len(p.Cloves))
	offset++

	// Cloves
	for _, clove := range p.Cloves {
		cloveBytes := clove.ToBytes()
		copy(buf[offset:], cloveBytes)
		offset += len(cloveBytes)
	}

	// Certificate (null certificate = 3 bytes of zeros)
	if len(p.Certificate) > 0 {
		copy(buf[offset:], p.Certificate)
		offset += len(p.Certificate)
	} else {
		buf[offset] = 0 // Null certificate type
		offset++
		binary.BigEndian.PutUint16(buf[offset:], 0) // Zero length
		offset += 2
	}

	// Message ID
	binary.BigEndian.PutUint32(buf[offset:], p.MsgID)
	offset += 4

	// Expiration
	binary.BigEndian.PutUint32(buf[offset:], uint32(p.Expiration/1000))

	return buf
}

// ParseGarlicPayload parses a decrypted garlic payload.
func ParseGarlicPayload(data []byte) (*GarlicPayload, error) {
	if len(data) < 1 {
		return nil, ErrMessageTooShort
	}

	payload := &GarlicPayload{}
	offset := 0

	// Number of cloves
	numCloves := int(data[offset])
	offset++

	// Parse cloves
	payload.Cloves = make([]*GarlicClove, 0, numCloves)
	for i := 0; i < numCloves; i++ {
		clove, bytesRead, err := ParseGarlicClove(data[offset:])
		if err != nil {
			return nil, err
		}
		payload.Cloves = append(payload.Cloves, clove)
		offset += bytesRead
	}

	// Certificate
	if len(data) < offset+3 {
		return nil, ErrMessageTooShort
	}
	certType := data[offset]
	certLen := int(binary.BigEndian.Uint16(data[offset+1:]))
	offset += 3

	if certType != 0 && certLen > 0 {
		if len(data) < offset+certLen {
			return nil, ErrMessageTooShort
		}
		payload.Certificate = make([]byte, certLen+3)
		payload.Certificate[0] = certType
		binary.BigEndian.PutUint16(payload.Certificate[1:], uint16(certLen))
		copy(payload.Certificate[3:], data[offset:offset+certLen])
		offset += certLen
	}

	// Message ID and Expiration
	if len(data) < offset+8 {
		return nil, ErrMessageTooShort
	}
	payload.MsgID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	payload.Expiration = int64(binary.BigEndian.Uint32(data[offset:])) * 1000

	return payload, nil
}

// NewLocalDeliveryClove creates a clove for local delivery.
func NewLocalDeliveryClove(msg []byte) *GarlicClove {
	return &GarlicClove{
		DeliveryType: GarlicDeliveryTypeLocal,
		MsgID:        GenerateMsgID(),
		Expiration:   time.Now().Add(MessageExpirationTimeout).UnixMilli(),
		Data:         msg,
	}
}

// NewTunnelDeliveryClove creates a clove for tunnel delivery.
func NewTunnelDeliveryClove(msg []byte, tunnelID uint32, gateway data.Hash) *GarlicClove {
	return &GarlicClove{
		DeliveryType: GarlicDeliveryTypeTunnel,
		TunnelID:     tunnelID,
		Gateway:      gateway,
		MsgID:        GenerateMsgID(),
		Expiration:   time.Now().Add(MessageExpirationTimeout).UnixMilli(),
		Data:         msg,
	}
}

// NewRouterDeliveryClove creates a clove for router delivery.
func NewRouterDeliveryClove(msg []byte, router data.Hash) *GarlicClove {
	return &GarlicClove{
		DeliveryType: GarlicDeliveryTypeRouter,
		ToHash:       router,
		MsgID:        GenerateMsgID(),
		Expiration:   time.Now().Add(MessageExpirationTimeout).UnixMilli(),
		Data:         msg,
	}
}

// NewDestinationDeliveryClove creates a clove for destination delivery.
func NewDestinationDeliveryClove(msg []byte, destination data.Hash) *GarlicClove {
	return &GarlicClove{
		DeliveryType: GarlicDeliveryTypeDestination,
		ToHash:       destination,
		MsgID:        GenerateMsgID(),
		Expiration:   time.Now().Add(MessageExpirationTimeout).UnixMilli(),
		Data:         msg,
	}
}
