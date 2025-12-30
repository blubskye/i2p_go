package i2np

import (
	"time"
)

// Data is a simple I2NP message carrying raw data.
// Used for streaming and datagram protocols.
type Data struct {
	Payload []byte
}

// NewData creates a new Data message.
func NewData(payload []byte) *Data {
	return &Data{
		Payload: payload,
	}
}

// ParseData parses a Data message from payload bytes.
func ParseData(payload []byte) (*Data, error) {
	return &Data{
		Payload: payload,
	}, nil
}

// Type returns TypeData.
func (d *Data) Type() MessageType {
	return TypeData
}

// GetMsgID returns 0.
func (d *Data) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (d *Data) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload returns the data payload.
func (d *Data) ToPayload() []byte {
	return d.Payload
}

// ToBytes serializes to a complete I2NP message.
func (d *Data) ToBytes() []byte {
	return NewRawMessage(TypeData, d.ToPayload()).ToBytes()
}
