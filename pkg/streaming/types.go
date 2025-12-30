// Package streaming implements the I2P streaming protocol (TCP-like streams over I2P).
package streaming

import (
	"errors"
	"time"
)

// Stream states
const (
	StateInit = iota
	StateSynSent
	StateEstablished
	StateClosing
	StateClosed
)

// Packet flags
const (
	FlagSynchronize = 1 << 0 // SYN - new stream
	FlagClose       = 1 << 1 // CLOSE - graceful close
	FlagReset       = 1 << 2 // RST - abort
	FlagSignature   = 1 << 3 // SIGNATURE_INCLUDED
	FlagFromIncl    = 1 << 4 // FROM_INCLUDED (Destination)
	FlagDelay       = 1 << 5 // DELAY_REQUESTED
	FlagMaxSize     = 1 << 6 // MAX_PACKET_SIZE_INCLUDED
	FlagOffline     = 1 << 7 // OFFLINE_SIGNATURE
	FlagEcho        = 1 << 8 // ECHO (ping)
	FlagNoAck       = 1 << 9 // NO_ACK (for intro)
)

// Protocol constants
const (
	ProtocolVersion = 1

	DefaultWindowSize     = 6
	MaxWindowSize         = 128
	DefaultMTU            = 1730
	MaxMTU                = 32768
	MinMTU                = 512

	DefaultRTT            = 2000 * time.Millisecond
	MinRTT                = 10 * time.Millisecond
	MaxRTT                = 120 * time.Second

	ConnectTimeout        = 60 * time.Second
	WriteTimeout          = 60 * time.Second
	ReadTimeout           = 60 * time.Second
	InactivityTimeout     = 300 * time.Second

	MaxSendQueue          = 64
	MaxReceiveQueue       = 64
	MaxResends            = 8

	ReceiveBufferSize     = 128 * 1024
	SendBufferSize        = 128 * 1024
)

// Errors
var (
	ErrStreamClosed     = errors.New("stream: closed")
	ErrStreamReset      = errors.New("stream: reset by peer")
	ErrConnectTimeout   = errors.New("stream: connect timeout")
	ErrWriteTimeout     = errors.New("stream: write timeout")
	ErrInvalidPacket    = errors.New("stream: invalid packet")
	ErrBufferFull       = errors.New("stream: buffer full")
	ErrNoDestination    = errors.New("stream: no destination")
	ErrNotEstablished   = errors.New("stream: not established")
)

// StreamID is a 4-byte stream identifier.
type StreamID uint32

// Packet represents a streaming protocol packet.
type Packet struct {
	SendStreamID    StreamID
	ReceiveStreamID StreamID
	SequenceNum     uint32
	AckThrough      uint32
	NACKCount       uint8
	NACKs           []uint32
	ResendDelay     uint8
	Flags           uint16
	OptionSize      uint16
	Options         []byte
	Payload         []byte

	// For processing
	signature       []byte
	fromDest        []byte
	maxPacketSize   uint16
}

// Options contains parsed packet options.
type Options struct {
	MaxPacketSize uint16
	OfflineSig    []byte
	Signature     []byte
	From          []byte
	Delay         uint16
}

// StreamStats contains stream statistics.
type StreamStats struct {
	State           int
	SendStreamID    StreamID
	ReceiveStreamID StreamID
	BytesSent       int64
	BytesReceived   int64
	PacketsSent     int64
	PacketsReceived int64
	Retransmits     int64
	RTT             time.Duration
	WindowSize      int
}
