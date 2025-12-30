package i2np

import (
	"encoding/binary"
	"time"
)

// DeliveryStatus message size
const DeliveryStatusSize = 12 // MsgID (4) + Timestamp (8)

// DeliveryStatus is sent to confirm message delivery.
type DeliveryStatus struct {
	MsgID     uint32
	Timestamp int64 // Milliseconds since epoch
}

// NewDeliveryStatus creates a new DeliveryStatus message.
func NewDeliveryStatus(msgID uint32) *DeliveryStatus {
	return &DeliveryStatus{
		MsgID:     msgID,
		Timestamp: time.Now().UnixMilli(),
	}
}

// ParseDeliveryStatus parses a DeliveryStatus from payload bytes.
func ParseDeliveryStatus(payload []byte) (*DeliveryStatus, error) {
	if len(payload) < DeliveryStatusSize {
		return nil, ErrMessageTooShort
	}

	return &DeliveryStatus{
		MsgID:     binary.BigEndian.Uint32(payload[0:4]),
		Timestamp: int64(binary.BigEndian.Uint64(payload[4:12])),
	}, nil
}

// Type returns TypeDeliveryStatus.
func (d *DeliveryStatus) Type() MessageType {
	return TypeDeliveryStatus
}

// GetMsgID returns the confirmed message ID.
func (d *DeliveryStatus) GetMsgID() uint32 {
	return d.MsgID
}

// GetExpiration returns the timestamp as expiration.
func (d *DeliveryStatus) GetExpiration() time.Time {
	return time.UnixMilli(d.Timestamp)
}

// ToPayload serializes the DeliveryStatus to payload bytes.
func (d *DeliveryStatus) ToPayload() []byte {
	buf := make([]byte, DeliveryStatusSize)
	binary.BigEndian.PutUint32(buf[0:4], d.MsgID)
	binary.BigEndian.PutUint64(buf[4:12], uint64(d.Timestamp))
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (d *DeliveryStatus) ToBytes() []byte {
	return NewRawMessage(TypeDeliveryStatus, d.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (d *DeliveryStatus) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeDeliveryStatus, d.ToPayload())
}
