// Package sam implements the SAMv3 protocol for client applications.
package sam

import (
	"errors"
)

// SAM protocol versions
const (
	SAMVersion31 = "3.1"
	SAMVersion32 = "3.2"
	SAMVersion33 = "3.3"
)

// SAM commands
const (
	CmdHello            = "HELLO"
	CmdSession          = "SESSION"
	CmdStream           = "STREAM"
	CmdDatagram         = "DATAGRAM"
	CmdRaw              = "RAW"
	CmdDest             = "DEST"
	CmdNaming           = "NAMING"
	CmdMasterSession    = "MASTER"
	CmdAuth             = "AUTH"
	CmdPing             = "PING"
	CmdPong             = "PONG"
)

// SAM reply result codes
const (
	ResultOK                = "OK"
	ResultCantReachPeer     = "CANT_REACH_PEER"
	ResultDuplicatedDest    = "DUPLICATED_DEST"
	ResultDuplicatedID      = "DUPLICATED_ID"
	ResultI2PError          = "I2P_ERROR"
	ResultInvalidID         = "INVALID_ID"
	ResultInvalidKey        = "INVALID_KEY"
	ResultKeyNotFound       = "KEY_NOT_FOUND"
	ResultPeerNotFound      = "PEER_NOT_FOUND"
	ResultTimeout           = "TIMEOUT"
)

// Session styles
const (
	StyleStream   = "STREAM"
	StyleDatagram = "DATAGRAM"
	StyleRaw      = "RAW"
)

// Default configuration
const (
	DefaultSAMAddress = "127.0.0.1:7656"
	DefaultInLength   = 3
	DefaultOutLength  = 3
	DefaultInQuantity = 2
	DefaultOutQuantity = 2
	DefaultInBackups  = 0
	DefaultOutBackups = 0
)

// I2CP options
const (
	OptInboundLength          = "inbound.length"
	OptOutboundLength         = "outbound.length"
	OptInboundQuantity        = "inbound.quantity"
	OptOutboundQuantity       = "outbound.quantity"
	OptInboundBackupQuantity  = "inbound.backupQuantity"
	OptOutboundBackupQuantity = "outbound.backupQuantity"
	OptSignatureType          = "SIGNATURE_TYPE"
	OptEncryptionType         = "i2cp.leaseSetEncType"
)

// Signature types
const (
	SigTypeDSA_SHA1          = 0
	SigTypeECDSA_P256        = 1
	SigTypeECDSA_P384        = 2
	SigTypeECDSA_P521        = 3
	SigTypeEdDSA_SHA512_Ed25519 = 7
)

// Errors
var (
	ErrInvalidReply     = errors.New("sam: invalid reply")
	ErrNotConnected     = errors.New("sam: not connected")
	ErrSessionExists    = errors.New("sam: session already exists")
	ErrNoSession        = errors.New("sam: no session")
	ErrCantReachPeer    = errors.New("sam: cannot reach peer")
	ErrTimeout          = errors.New("sam: timeout")
	ErrInvalidKey       = errors.New("sam: invalid key")
	ErrKeyNotFound      = errors.New("sam: key not found")
	ErrPeerNotFound     = errors.New("sam: peer not found")
	ErrI2PError         = errors.New("sam: I2P error")
	ErrDuplicatedDest   = errors.New("sam: duplicated destination")
	ErrDuplicatedID     = errors.New("sam: duplicated ID")
	ErrInvalidID        = errors.New("sam: invalid ID")
)

// SessionConfig holds session configuration.
type SessionConfig struct {
	Style            string
	InboundLength    int
	OutboundLength   int
	InboundQuantity  int
	OutboundQuantity int
	InboundBackups   int
	OutboundBackups  int
	SignatureType    int
	EncryptionType   string
	ReduceIdle       bool
	ReduceIdleTime   int
	ReduceQuantity   int
	CloseIdle        bool
	CloseIdleTime    int
}

// DefaultSessionConfig returns the default session configuration.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		Style:            StyleStream,
		InboundLength:    DefaultInLength,
		OutboundLength:   DefaultOutLength,
		InboundQuantity:  DefaultInQuantity,
		OutboundQuantity: DefaultOutQuantity,
		InboundBackups:   DefaultInBackups,
		OutboundBackups:  DefaultOutBackups,
		SignatureType:    SigTypeEdDSA_SHA512_Ed25519,
		EncryptionType:   "4", // ECIES-X25519-AEAD
	}
}

// Reply represents a SAM reply.
type Reply struct {
	Topic   string
	Type    string
	Result  string
	Values  map[string]string
	Message string
}

// IsOK returns true if the reply indicates success.
func (r *Reply) IsOK() bool {
	return r.Result == ResultOK
}

// GetError returns an error based on the result code.
func (r *Reply) GetError() error {
	switch r.Result {
	case ResultOK:
		return nil
	case ResultCantReachPeer:
		return ErrCantReachPeer
	case ResultDuplicatedDest:
		return ErrDuplicatedDest
	case ResultDuplicatedID:
		return ErrDuplicatedID
	case ResultI2PError:
		return ErrI2PError
	case ResultInvalidID:
		return ErrInvalidID
	case ResultInvalidKey:
		return ErrInvalidKey
	case ResultKeyNotFound:
		return ErrKeyNotFound
	case ResultPeerNotFound:
		return ErrPeerNotFound
	case ResultTimeout:
		return ErrTimeout
	default:
		return ErrI2PError
	}
}
