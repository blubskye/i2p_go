// Package ssu2 implements the SSU2 transport protocol for I2P.
// SSU2 is a UDP-based transport with built-in NAT traversal.
package ssu2

import (
	"errors"
	"time"
)

// Protocol constants
const (
	MaxPacketSize = 1500
	MinPacketSize = 1280
)

// Timeout constants
const (
	ConnectTimeout              = 5 * time.Second
	TerminationTimeout          = 165 * time.Second
	ClockSkew                   = 60 * time.Second
	ClockThreshold              = 15 * time.Second
	TokenExpiration             = 9 * time.Second
	NextTokenExpiration         = 52 * 60 * time.Second
	TokenExpirationThreshold    = 2 * time.Second
	RelayNonceExpiration        = 10 * time.Second
	PeerTestExpiration          = 60 * time.Second
	HandshakeResendInterval     = 1000 * time.Millisecond
	ResendAttemptMinInterval    = 3 * time.Millisecond
	IncompleteMessagesCleanup   = 30 * time.Second
	ReceivedMsgIDsCleanup       = 10 * time.Second
	DecayInterval               = 20 * time.Second
)

// Congestion control constants
const (
	MaxNumResends       = 5
	MinWindowSize       = 16
	MaxWindowSize       = 256
	MinRTO              = 100 * time.Millisecond
	InitialRTO          = 540 * time.Millisecond
	MaxRTO              = 2500 * time.Millisecond
	RTTEWMAAlpha        = 0.125
	Kappa               = 1.8
	MaxNumACNT          = 255
	MaxNumACKPackets    = 511
	MaxNumACKRanges     = 32
	MaxNumFragments     = 64
	SendDateTimePackets = 256
	MaxReceivedMsgIDs   = 5000
)

// Flags
const (
	FlagImmediateACKRequested uint8 = 0x01
)

// MessageType represents an SSU2 message type.
type MessageType uint8

const (
	MsgSessionRequest   MessageType = 0
	MsgSessionCreated   MessageType = 1
	MsgSessionConfirmed MessageType = 2
	MsgData             MessageType = 6
	MsgPeerTest         MessageType = 7
	MsgRetry            MessageType = 9
	MsgTokenRequest     MessageType = 10
	MsgHolePunch        MessageType = 11
)

// String returns the message type name.
func (m MessageType) String() string {
	switch m {
	case MsgSessionRequest:
		return "SessionRequest"
	case MsgSessionCreated:
		return "SessionCreated"
	case MsgSessionConfirmed:
		return "SessionConfirmed"
	case MsgData:
		return "Data"
	case MsgPeerTest:
		return "PeerTest"
	case MsgRetry:
		return "Retry"
	case MsgTokenRequest:
		return "TokenRequest"
	case MsgHolePunch:
		return "HolePunch"
	default:
		return "Unknown"
	}
}

// BlockType represents an SSU2 block type.
type BlockType uint8

const (
	BlockDateTime         BlockType = 0
	BlockOptions          BlockType = 1
	BlockRouterInfo       BlockType = 2
	BlockI2NPMessage      BlockType = 3
	BlockFirstFragment    BlockType = 4
	BlockFollowOnFragment BlockType = 5
	BlockTermination      BlockType = 6
	BlockRelayRequest     BlockType = 7
	BlockRelayResponse    BlockType = 8
	BlockRelayIntro       BlockType = 9
	BlockPeerTest         BlockType = 10
	BlockNextNonce        BlockType = 11
	BlockACK              BlockType = 12
	BlockAddress          BlockType = 13
	BlockIntroKey         BlockType = 14
	BlockRelayTagRequest  BlockType = 15
	BlockRelayTag         BlockType = 16
	BlockNewToken         BlockType = 17
	BlockPathChallenge    BlockType = 18
	BlockPathResponse     BlockType = 19
	BlockFirstPacketNum   BlockType = 20
	BlockPadding          BlockType = 254
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
	case BlockFirstFragment:
		return "FirstFragment"
	case BlockFollowOnFragment:
		return "FollowOnFragment"
	case BlockTermination:
		return "Termination"
	case BlockRelayRequest:
		return "RelayRequest"
	case BlockRelayResponse:
		return "RelayResponse"
	case BlockRelayIntro:
		return "RelayIntro"
	case BlockPeerTest:
		return "PeerTest"
	case BlockNextNonce:
		return "NextNonce"
	case BlockACK:
		return "ACK"
	case BlockAddress:
		return "Address"
	case BlockIntroKey:
		return "IntroKey"
	case BlockRelayTagRequest:
		return "RelayTagRequest"
	case BlockRelayTag:
		return "RelayTag"
	case BlockNewToken:
		return "NewToken"
	case BlockPathChallenge:
		return "PathChallenge"
	case BlockPathResponse:
		return "PathResponse"
	case BlockFirstPacketNum:
		return "FirstPacketNumber"
	case BlockPadding:
		return "Padding"
	default:
		return "Unknown"
	}
}

// SessionState represents the state of an SSU2 session.
type SessionState int

const (
	StateUnknown SessionState = iota
	StateTokenReceived
	StateSessionRequestSent
	StateSessionRequestReceived
	StateSessionCreatedSent
	StateSessionCreatedReceived
	StateSessionConfirmedSent
	StateEstablished
	StateClosing
	StateClosingConfirmed
	StateTerminated
	StateFailed
	StateIntroduced
	StateHolePunch
	StatePeerTest
	StateTokenRequestReceived
)

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
	TermSessionRequestError             TerminationReason = 11
	TermSessionCreatedError             TerminationReason = 12
	TermSessionConfirmedError           TerminationReason = 13
	TermTimeout                         TerminationReason = 14
	TermRouterInfoSignatureVerifyFailed TerminationReason = 15
	TermInvalidS                        TerminationReason = 16
	TermBanned                          TerminationReason = 17
	TermBadToken                        TerminationReason = 18
	TermConnectionLimits                TerminationReason = 19
	TermIncompatibleVersion             TerminationReason = 20
	TermWrongNetID                      TerminationReason = 21
	TermReplacedByNewSession            TerminationReason = 22
)

// PeerTestCode represents the result of a peer test.
type PeerTestCode uint8

const (
	PeerTestAccept                      PeerTestCode = 0
	PeerTestBobReasonUnspecified        PeerTestCode = 1
	PeerTestBobNoCharlieAvailable       PeerTestCode = 2
	PeerTestBobLimitExceeded            PeerTestCode = 3
	PeerTestBobSignatureFailure         PeerTestCode = 4
	PeerTestCharlieReasonUnspecified    PeerTestCode = 64
	PeerTestCharlieUnsupportedAddress   PeerTestCode = 65
	PeerTestCharlieLimitExceeded        PeerTestCode = 66
	PeerTestCharlieSignatureFailure     PeerTestCode = 67
	PeerTestCharlieAliceIsConnected     PeerTestCode = 68
	PeerTestCharlieAliceIsBanned        PeerTestCode = 69
	PeerTestCharlieAliceIsUnknown       PeerTestCode = 70
	PeerTestUnspecified                 PeerTestCode = 128
)

// Header constants
const (
	HeaderSize          = 16  // Destination(8) + PacketNumber(4) + Type(1) + Flags(3)
	ShortHeaderSize     = 16  // For data packets
	LongHeaderSize      = 32  // For handshake packets
	ConnectionIDSize    = 8
	PacketNumberSize    = 4
)

// Errors
var (
	ErrHandshakeFailed     = errors.New("ssu2: handshake failed")
	ErrInvalidPacket       = errors.New("ssu2: invalid packet")
	ErrDecryptionFailed    = errors.New("ssu2: decryption failed")
	ErrAuthenticationFailed = errors.New("ssu2: authentication failed")
	ErrClockSkew           = errors.New("ssu2: clock skew too large")
	ErrSessionTerminated   = errors.New("ssu2: session terminated")
	ErrTimeout             = errors.New("ssu2: timeout")
	ErrInvalidBlockType    = errors.New("ssu2: invalid block type")
	ErrPacketTooLarge      = errors.New("ssu2: packet too large")
	ErrBadToken            = errors.New("ssu2: bad token")
)

// CongestionState tracks congestion control state.
type CongestionState struct {
	WindowSize       int
	RTT              float64 // Round-trip time in milliseconds
	RTTVAR           float64 // RTT variance
	RTO              time.Duration
	SlowStartThresh  int
	InSlowStart      bool
	LastAckTime      time.Time
	LastSendTime     time.Time
	UnackedPackets   int
	DuplicateAckCount int
}

// NewCongestionState creates a new congestion control state.
func NewCongestionState() *CongestionState {
	return &CongestionState{
		WindowSize:      MinWindowSize,
		RTT:             -1, // Unknown
		RTO:             InitialRTO,
		SlowStartThresh: MaxWindowSize,
		InSlowStart:     true,
	}
}

// UpdateRTT updates the RTT estimate using EWMA.
func (c *CongestionState) UpdateRTT(sample time.Duration) {
	sampleMS := float64(sample.Milliseconds())

	if c.RTT < 0 {
		// First measurement
		c.RTT = sampleMS
		c.RTTVAR = sampleMS / 2
	} else {
		// EWMA update
		c.RTTVAR = (1-RTTEWMAAlpha)*c.RTTVAR + RTTEWMAAlpha*abs(c.RTT-sampleMS)
		c.RTT = (1-RTTEWMAAlpha)*c.RTT + RTTEWMAAlpha*sampleMS
	}

	// Calculate RTO
	rto := c.RTT + Kappa*c.RTTVAR
	if rto < float64(MinRTO.Milliseconds()) {
		rto = float64(MinRTO.Milliseconds())
	}
	if rto > float64(MaxRTO.Milliseconds()) {
		rto = float64(MaxRTO.Milliseconds())
	}
	c.RTO = time.Duration(rto) * time.Millisecond
}

// OnPacketAcked handles a packet being acknowledged.
func (c *CongestionState) OnPacketAcked() {
	c.UnackedPackets--
	c.DuplicateAckCount = 0
	c.LastAckTime = time.Now()

	if c.InSlowStart {
		c.WindowSize++
		if c.WindowSize >= c.SlowStartThresh {
			c.InSlowStart = false
		}
	} else {
		// Congestion avoidance - increase window by 1/window per ACK
		// This approximates 1 per RTT
	}

	if c.WindowSize > MaxWindowSize {
		c.WindowSize = MaxWindowSize
	}
}

// OnPacketLost handles a packet being lost.
func (c *CongestionState) OnPacketLost() {
	c.SlowStartThresh = c.WindowSize / 2
	if c.SlowStartThresh < MinWindowSize {
		c.SlowStartThresh = MinWindowSize
	}
	c.WindowSize = MinWindowSize
	c.InSlowStart = false
	c.RTO *= 2
	if c.RTO > MaxRTO {
		c.RTO = MaxRTO
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
