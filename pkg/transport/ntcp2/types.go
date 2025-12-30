// Package ntcp2 implements the NTCP2 transport protocol for I2P.
package ntcp2

import (
	"errors"
	"time"
)

// Protocol constants
const (
	UnencryptedFrameMaxSize = 65519
	SendAfterFrameSize      = 16386 // Send frame when exceeds this size
	SessionRequestMaxSize   = 287
	SessionCreatedMaxSize   = 287

	MaxPaddingRatio = 6 // in percent
)

// Timeout constants
const (
	ConnectTimeout               = 5 * time.Second
	EstablishTimeout             = 10 * time.Second
	TerminationTimeout           = 115 * time.Second // 2 minutes - 5 seconds
	TerminationTimeoutVariance   = 10 * time.Second
	TerminationCheckTimeout      = 28 * time.Second
	TerminationCheckVariance     = 5 * time.Second
	ReceiveBufferDeletionTimeout = 3 * time.Second
	RouterInfoResendInterval     = 25 * 60 * time.Second // 25 minutes
	ClockSkew                    = 60 * time.Second
)

// Protocol limits
const (
	MaxOutgoingQueueSize = 500
)

// Frame header sizes
const (
	FrameLengthSize = 2  // Encrypted length field
	FrameMACSize    = 16 // Poly1305 MAC
	MinFrameSize    = FrameLengthSize + FrameMACSize
)

// BlockType represents an NTCP2 block type.
type BlockType uint8

const (
	BlockDateTime    BlockType = 0
	BlockOptions     BlockType = 1
	BlockRouterInfo  BlockType = 2
	BlockI2NPMessage BlockType = 3
	BlockTermination BlockType = 4
	BlockPadding     BlockType = 254
)

// String returns the block type name.
func (b BlockType) String() string {
	switch b {
	case BlockDateTime:
		return "DateTime"
	case BlockOptions:
		return "Options"
	case BlockRouterInfo:
		return "RouterInfo"
	case BlockI2NPMessage:
		return "I2NPMessage"
	case BlockTermination:
		return "Termination"
	case BlockPadding:
		return "Padding"
	default:
		return "Unknown"
	}
}

// TerminationReason represents why a session was terminated.
type TerminationReason uint8

const (
	TermNormalClose                     TerminationReason = 0
	TermTerminationReceived             TerminationReason = 1
	TermIdleTimeout                     TerminationReason = 2
	TermRouterShutdown                  TerminationReason = 3
	TermDataPhaseAEADFailure            TerminationReason = 4
	TermIncompatibleOptions             TerminationReason = 5
	TermIncompatibleSignatureType       TerminationReason = 6
	TermClockSkew                       TerminationReason = 7
	TermPaddingViolation                TerminationReason = 8
	TermAEADFramingError                TerminationReason = 9
	TermPayloadFormatError              TerminationReason = 10
	TermMessage1Error                   TerminationReason = 11
	TermMessage2Error                   TerminationReason = 12
	TermMessage3Error                   TerminationReason = 13
	TermIntraFrameReadTimeout           TerminationReason = 14
	TermRouterInfoSignatureVerifyFailed TerminationReason = 15
	TermIncorrectSParameter             TerminationReason = 16
	TermBanned                          TerminationReason = 17
)

// String returns the termination reason description.
func (r TerminationReason) String() string {
	switch r {
	case TermNormalClose:
		return "Normal close"
	case TermTerminationReceived:
		return "Termination received"
	case TermIdleTimeout:
		return "Idle timeout"
	case TermRouterShutdown:
		return "Router shutdown"
	case TermDataPhaseAEADFailure:
		return "Data phase AEAD failure"
	case TermIncompatibleOptions:
		return "Incompatible options"
	case TermIncompatibleSignatureType:
		return "Incompatible signature type"
	case TermClockSkew:
		return "Clock skew"
	case TermPaddingViolation:
		return "Padding violation"
	case TermAEADFramingError:
		return "AEAD framing error"
	case TermPayloadFormatError:
		return "Payload format error"
	case TermMessage1Error:
		return "Message 1 error"
	case TermMessage2Error:
		return "Message 2 error"
	case TermMessage3Error:
		return "Message 3 error"
	case TermIntraFrameReadTimeout:
		return "Intra-frame read timeout"
	case TermRouterInfoSignatureVerifyFailed:
		return "RouterInfo signature verification failed"
	case TermIncorrectSParameter:
		return "Incorrect S parameter"
	case TermBanned:
		return "Banned"
	default:
		return "Unknown"
	}
}

// RouterInfo flags
const (
	RouterInfoFlagRequestFlood uint8 = 0x01
)

// Session options from Options block
type SessionOptions struct {
	TMIN   uint16 // Minimum padding size
	TMAX   uint16 // Maximum padding size
	RMIN   uint16 // Minimum RouterInfo size
	RMAX   uint16 // Maximum RouterInfo size
	TDUMMY uint16 // Dummy traffic interval (0 = disabled)
	TDELAY uint16 // Maximum delay for bundling
	M      uint8  // Version and features
}

// DefaultOptions returns default session options.
func DefaultOptions() *SessionOptions {
	return &SessionOptions{
		TMIN:   0,
		TMAX:   0,
		RMIN:   0,
		RMAX:   0,
		TDUMMY: 0,
		TDELAY: 0,
		M:      0,
	}
}

// Errors
var (
	ErrHandshakeFailed     = errors.New("ntcp2: handshake failed")
	ErrInvalidMessage      = errors.New("ntcp2: invalid message")
	ErrDecryptionFailed    = errors.New("ntcp2: decryption failed")
	ErrAuthenticationFailed = errors.New("ntcp2: authentication failed")
	ErrClockSkew           = errors.New("ntcp2: clock skew too large")
	ErrSessionTerminated   = errors.New("ntcp2: session terminated")
	ErrTimeout             = errors.New("ntcp2: timeout")
	ErrInvalidBlockType    = errors.New("ntcp2: invalid block type")
	ErrFrameTooLarge       = errors.New("ntcp2: frame too large")
	ErrConnectionClosed    = errors.New("ntcp2: connection closed")
)
