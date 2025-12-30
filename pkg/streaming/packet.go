package streaming

import (
	"encoding/binary"
)

// PacketHeaderSize is the minimum packet header size (without options).
const PacketHeaderSize = 22

// ParsePacket parses a streaming packet from bytes.
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < PacketHeaderSize {
		return nil, ErrInvalidPacket
	}

	p := &Packet{}
	offset := 0

	// Send stream ID (4 bytes)
	p.SendStreamID = StreamID(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// Receive stream ID (4 bytes)
	p.ReceiveStreamID = StreamID(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// Sequence number (4 bytes)
	p.SequenceNum = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Ack through (4 bytes)
	p.AckThrough = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// NACK count (1 byte)
	p.NACKCount = data[offset]
	offset++

	// Resend delay (1 byte)
	p.ResendDelay = data[offset]
	offset++

	// Flags (2 bytes)
	p.Flags = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Option size (2 bytes)
	p.OptionSize = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Parse NACKs if any
	if p.NACKCount > 0 {
		nackSize := int(p.NACKCount) * 4
		if len(data) < offset+nackSize {
			return nil, ErrInvalidPacket
		}
		p.NACKs = make([]uint32, p.NACKCount)
		for i := 0; i < int(p.NACKCount); i++ {
			p.NACKs[i] = binary.BigEndian.Uint32(data[offset:])
			offset += 4
		}
	}

	// Parse options if any
	if p.OptionSize > 0 {
		if len(data) < offset+int(p.OptionSize) {
			return nil, ErrInvalidPacket
		}
		p.Options = make([]byte, p.OptionSize)
		copy(p.Options, data[offset:offset+int(p.OptionSize)])
		offset += int(p.OptionSize)

		// Parse option contents based on flags
		p.parseOptions()
	}

	// Remaining data is payload
	if len(data) > offset {
		p.Payload = make([]byte, len(data)-offset)
		copy(p.Payload, data[offset:])
	}

	return p, nil
}

// parseOptions parses option bytes based on flags.
func (p *Packet) parseOptions() {
	offset := 0
	options := p.Options

	// MAX_PACKET_SIZE (2 bytes if flag set)
	if p.Flags&FlagMaxSize != 0 && len(options) >= offset+2 {
		p.maxPacketSize = binary.BigEndian.Uint16(options[offset:])
		offset += 2
	}

	// DELAY_REQUESTED (2 bytes if flag set)
	if p.Flags&FlagDelay != 0 && len(options) >= offset+2 {
		// delay := binary.BigEndian.Uint16(options[offset:])
		offset += 2
	}

	// FROM_INCLUDED (variable, Destination)
	if p.Flags&FlagFromIncl != 0 {
		// Destination is at least 387 bytes (standard identity)
		// For now, store the remaining bytes as from
		if len(options) > offset {
			p.fromDest = options[offset:]
		}
	}

	// SIGNATURE_INCLUDED (40-64 bytes depending on sig type)
	if p.Flags&FlagSignature != 0 {
		// Ed25519 signature is 64 bytes
		// For now, assume rest is signature if fromDest not set
		if p.fromDest == nil && len(options) > offset {
			p.signature = options[offset:]
		}
	}
}

// ToBytes serializes a packet to bytes.
func (p *Packet) ToBytes() []byte {
	// Calculate size
	size := PacketHeaderSize
	size += int(p.NACKCount) * 4
	size += int(p.OptionSize)
	size += len(p.Payload)

	buf := make([]byte, size)
	offset := 0

	// Send stream ID
	binary.BigEndian.PutUint32(buf[offset:], uint32(p.SendStreamID))
	offset += 4

	// Receive stream ID
	binary.BigEndian.PutUint32(buf[offset:], uint32(p.ReceiveStreamID))
	offset += 4

	// Sequence number
	binary.BigEndian.PutUint32(buf[offset:], p.SequenceNum)
	offset += 4

	// Ack through
	binary.BigEndian.PutUint32(buf[offset:], p.AckThrough)
	offset += 4

	// NACK count
	buf[offset] = p.NACKCount
	offset++

	// Resend delay
	buf[offset] = p.ResendDelay
	offset++

	// Flags
	binary.BigEndian.PutUint16(buf[offset:], p.Flags)
	offset += 2

	// Option size
	binary.BigEndian.PutUint16(buf[offset:], p.OptionSize)
	offset += 2

	// NACKs
	for _, nack := range p.NACKs {
		binary.BigEndian.PutUint32(buf[offset:], nack)
		offset += 4
	}

	// Options
	if len(p.Options) > 0 {
		copy(buf[offset:], p.Options)
		offset += len(p.Options)
	}

	// Payload
	if len(p.Payload) > 0 {
		copy(buf[offset:], p.Payload)
	}

	return buf
}

// IsSYN returns true if this is a SYN packet.
func (p *Packet) IsSYN() bool {
	return p.Flags&FlagSynchronize != 0
}

// IsClose returns true if this is a close packet.
func (p *Packet) IsClose() bool {
	return p.Flags&FlagClose != 0
}

// IsReset returns true if this is a reset packet.
func (p *Packet) IsReset() bool {
	return p.Flags&FlagReset != 0
}

// IsEcho returns true if this is an echo (ping) packet.
func (p *Packet) IsEcho() bool {
	return p.Flags&FlagEcho != 0
}

// HasSignature returns true if packet includes signature.
func (p *Packet) HasSignature() bool {
	return p.Flags&FlagSignature != 0
}

// HasFrom returns true if packet includes source destination.
func (p *Packet) HasFrom() bool {
	return p.Flags&FlagFromIncl != 0
}

// GetMaxPacketSize returns the max packet size from options.
func (p *Packet) GetMaxPacketSize() uint16 {
	return p.maxPacketSize
}

// NewSYNPacket creates a new SYN packet.
func NewSYNPacket(sendID StreamID, options []byte) *Packet {
	p := &Packet{
		SendStreamID:    sendID,
		ReceiveStreamID: 0,
		SequenceNum:     0,
		AckThrough:      0,
		Flags:           FlagSynchronize | FlagSignature | FlagFromIncl | FlagMaxSize,
		Options:         options,
		OptionSize:      uint16(len(options)),
	}
	return p
}

// NewDataPacket creates a new data packet.
func NewDataPacket(sendID, recvID StreamID, seqNum, ackThrough uint32, payload []byte) *Packet {
	return &Packet{
		SendStreamID:    sendID,
		ReceiveStreamID: recvID,
		SequenceNum:     seqNum,
		AckThrough:      ackThrough,
		Payload:         payload,
	}
}

// NewAckPacket creates an ACK-only packet.
func NewAckPacket(sendID, recvID StreamID, ackThrough uint32) *Packet {
	return &Packet{
		SendStreamID:    sendID,
		ReceiveStreamID: recvID,
		SequenceNum:     0, // Not incrementing for pure ACK
		AckThrough:      ackThrough,
	}
}

// NewClosePacket creates a close packet.
func NewClosePacket(sendID, recvID StreamID, seqNum, ackThrough uint32) *Packet {
	return &Packet{
		SendStreamID:    sendID,
		ReceiveStreamID: recvID,
		SequenceNum:     seqNum,
		AckThrough:      ackThrough,
		Flags:           FlagClose,
	}
}

// NewResetPacket creates a reset packet.
func NewResetPacket(sendID, recvID StreamID) *Packet {
	return &Packet{
		SendStreamID:    sendID,
		ReceiveStreamID: recvID,
		Flags:           FlagReset,
	}
}
