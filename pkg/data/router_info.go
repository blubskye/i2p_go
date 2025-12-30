package data

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// RouterInfo property keys
const (
	PropertyNetID      = "netId"
	PropertyVersion    = "router.version"
	PropertyFamily     = "family"
	PropertyFamilySig  = "family.sig"
	PropertyKnownLeaseSets = "netdb.knownLeaseSets"
	PropertyKnownRouters   = "netdb.knownRouters"
)

// Capability flags
const (
	CapsFlagFloodfill       = 'f'
	CapsFlagHidden          = 'H'
	CapsFlagReachable       = 'R'
	CapsFlagUnreachable     = 'U'

	// Bandwidth flags
	CapsFlagBandwidthK = 'K' // < 12 KBps
	CapsFlagBandwidthL = 'L' // 12-48 KBps
	CapsFlagBandwidthM = 'M' // 48-64 KBps
	CapsFlagBandwidthN = 'N' // 64-128 KBps
	CapsFlagBandwidthO = 'O' // 128-256 KBps
	CapsFlagBandwidthP = 'P' // 256-2048 KBps
	CapsFlagBandwidthX = 'X' // > 2048 KBps

	// Congestion flags
	CapsFlagMediumCongestion = 'D'
	CapsFlagHighCongestion   = 'E'
	CapsFlagRejectAll        = 'G'

	// Address flags
	CapsFlagV4           = '4'
	CapsFlagV6           = '6'
	CapsFlagSSU2Testing  = 'B'
	CapsFlagSSU2Introducer = 'C'
)

// Caps is a bitmask of router capabilities
type Caps uint8

const (
	CapsFloodfill     Caps = 0x01
	CapsHighBandwidth Caps = 0x02
	CapsExtraBandwidth Caps = 0x04
	CapsReachable     Caps = 0x08
	CapsHidden        Caps = 0x10
	CapsUnreachable   Caps = 0x20
)

// Congestion level
type Congestion uint8

const (
	CongestionLow Congestion = iota
	CongestionMedium
	CongestionHigh
	CongestionRejectAll
)

// Transport style
type TransportStyle uint8

const (
	TransportUnknown TransportStyle = iota
	TransportNTCP2
	TransportSSU2
)

// String returns the transport style name.
func (t TransportStyle) String() string {
	switch t {
	case TransportNTCP2:
		return "NTCP2"
	case TransportSSU2:
		return "SSU2"
	default:
		return "Unknown"
	}
}

// Address capabilities
type AddressCaps uint8

const (
	AddressCapsV4         AddressCaps = 0x01
	AddressCapsV6         AddressCaps = 0x02
	AddressCapsSSUTesting AddressCaps = 0x04
	AddressCapsSSUIntro   AddressCaps = 0x08
)

// Supported transports bitmask
type SupportedTransports uint8

const (
	TransportNTCP2V4     SupportedTransports = 0x01
	TransportNTCP2V6     SupportedTransports = 0x02
	TransportSSU2V4      SupportedTransports = 0x04
	TransportSSU2V6      SupportedTransports = 0x08
	TransportNTCP2V6Mesh SupportedTransports = 0x10
	TransportAll         SupportedTransports = 0xFF
)

// Cost constants for address selection
const (
	CostNTCP2Published    = 3
	CostNTCP2NonPublished = 14
	CostSSU2Direct        = 8
	CostSSU2NonPublished  = 15
)

// Maximum RouterInfo buffer size
const MaxRouterInfoSize = 3072

var (
	ErrInvalidRouterInfo = errors.New("data: invalid router info")
	ErrRouterInfoTooLarge = errors.New("data: router info too large")
)

// Introducer represents an SSU2 introducer.
type Introducer struct {
	Hash Hash
	Tag  uint32
	Exp  uint32
}

// SSUExt contains SSU2-specific address data.
type SSUExt struct {
	MTU         int
	Introducers []Introducer
}

// RouterAddress represents a router transport address.
type RouterAddress struct {
	TransportStyle TransportStyle
	Host           net.IP
	Port           int
	StaticKey      [32]byte // 's' option for NTCP2/SSU2
	IntroKey       [32]byte // 'i' option (16 bytes for NTCP2, 32 for SSU2)
	Version        int      // Protocol version
	Date           uint64   // For introducers
	Caps           AddressCaps
	Published      bool
	Cost           uint8
	SSU            *SSUExt // Non-nil for SSU2
	Options        map[string]string
}

// IsNTCP2 returns true if this is an NTCP2 address.
func (a *RouterAddress) IsNTCP2() bool {
	return a.TransportStyle == TransportNTCP2
}

// IsSSU2 returns true if this is an SSU2 address.
func (a *RouterAddress) IsSSU2() bool {
	return a.TransportStyle == TransportSSU2
}

// IsV4 returns true if this is an IPv4 address.
func (a *RouterAddress) IsV4() bool {
	return (a.Caps&AddressCapsV4) != 0 || (a.Host != nil && a.Host.To4() != nil)
}

// IsV6 returns true if this is an IPv6 address.
func (a *RouterAddress) IsV6() bool {
	return (a.Caps&AddressCapsV6) != 0 || (a.Host != nil && a.Host.To4() == nil && a.Host.To16() != nil)
}

// IsPublished returns true if this address is published.
func (a *RouterAddress) IsPublished() bool {
	return a.Published
}

// IsIntroducer returns true if this address is an SSU2 introducer.
func (a *RouterAddress) IsIntroducer() bool {
	return (a.Caps & AddressCapsSSUIntro) != 0
}

// IsPeerTesting returns true if this address supports peer testing.
func (a *RouterAddress) IsPeerTesting() bool {
	return (a.Caps & AddressCapsSSUTesting) != 0
}

// UsesIntroducer returns true if this address uses introducers.
func (a *RouterAddress) UsesIntroducer() bool {
	return a.SSU != nil && len(a.SSU.Introducers) > 0
}

// RouterInfo represents I2P router information.
type RouterInfo struct {
	Identity   *IdentityEx
	Timestamp  int64 // Milliseconds since epoch
	Addresses  []*RouterAddress
	Properties map[string]string
	Signature  []byte

	// Computed fields
	identHash         IdentHash
	hashComputed      bool
	caps              Caps
	congestion        Congestion
	version           int
	supportedTransports SupportedTransports

	// Raw buffer for re-serialization
	rawBuffer []byte
}

// NewRouterInfo creates a new RouterInfo from a buffer.
func NewRouterInfo(buf []byte) (*RouterInfo, error) {
	ri := &RouterInfo{}
	_, err := ri.FromBuffer(buf)
	if err != nil {
		return nil, err
	}
	return ri, nil
}

// FromBuffer parses a RouterInfo from a byte buffer.
func (ri *RouterInfo) FromBuffer(buf []byte) (int, error) {
	if len(buf) > MaxRouterInfoSize {
		return 0, ErrRouterInfoTooLarge
	}

	offset := 0

	// Parse identity
	ri.Identity = &IdentityEx{}
	n, err := ri.Identity.FromBuffer(buf[offset:])
	if err != nil {
		return 0, err
	}
	offset += n

	// Parse timestamp (8 bytes, big-endian, milliseconds)
	if len(buf) < offset+8 {
		return 0, ErrBufferTooShort
	}
	ri.Timestamp = int64(binary.BigEndian.Uint64(buf[offset:]))
	offset += 8

	// Parse addresses
	if len(buf) < offset+1 {
		return 0, ErrBufferTooShort
	}
	numAddresses := int(buf[offset])
	offset++

	ri.Addresses = make([]*RouterAddress, 0, numAddresses)
	for i := 0; i < numAddresses; i++ {
		addr := &RouterAddress{Options: make(map[string]string)}
		n, err := ri.parseAddress(buf[offset:], addr)
		if err != nil {
			return 0, err
		}
		offset += n
		ri.Addresses = append(ri.Addresses, addr)
	}

	// Parse properties (mapping)
	if len(buf) < offset+2 {
		return 0, ErrBufferTooShort
	}
	propsSize := int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2

	ri.Properties = make(map[string]string)
	propsEnd := offset + propsSize
	if len(buf) < propsEnd {
		return 0, ErrBufferTooShort
	}

	for offset < propsEnd {
		// Read key
		if len(buf) < offset+1 {
			break
		}
		keyLen := int(buf[offset])
		offset++
		if len(buf) < offset+keyLen+1 {
			break
		}
		key := string(buf[offset : offset+keyLen])
		offset += keyLen

		// Skip '='
		if buf[offset] != '=' {
			return 0, ErrInvalidRouterInfo
		}
		offset++

		// Read value
		if len(buf) < offset+1 {
			break
		}
		valLen := int(buf[offset])
		offset++
		if len(buf) < offset+valLen+1 {
			break
		}
		val := string(buf[offset : offset+valLen])
		offset += valLen

		// Skip ';'
		if buf[offset] != ';' {
			return 0, ErrInvalidRouterInfo
		}
		offset++

		ri.Properties[key] = val
	}

	// Parse signature
	sigLen := ri.Identity.GetSignatureLen()
	if sigLen == 0 {
		sigLen = 40 // Default DSA signature length
	}
	if len(buf) < offset+sigLen {
		return 0, ErrBufferTooShort
	}
	ri.Signature = make([]byte, sigLen)
	copy(ri.Signature, buf[offset:offset+sigLen])
	offset += sigLen

	// Store raw buffer and compute fields
	ri.rawBuffer = make([]byte, offset)
	copy(ri.rawBuffer, buf[:offset])
	ri.computeFields()

	return offset, nil
}

// parseAddress parses a single RouterAddress from a buffer.
func (ri *RouterInfo) parseAddress(buf []byte, addr *RouterAddress) (int, error) {
	offset := 0

	// Cost (1 byte)
	if len(buf) < 1 {
		return 0, ErrBufferTooShort
	}
	addr.Cost = buf[offset]
	offset++

	// Expiration date (8 bytes)
	if len(buf) < offset+8 {
		return 0, ErrBufferTooShort
	}
	addr.Date = binary.BigEndian.Uint64(buf[offset:])
	offset += 8

	// Transport style (string)
	if len(buf) < offset+1 {
		return 0, ErrBufferTooShort
	}
	styleLen := int(buf[offset])
	offset++
	if len(buf) < offset+styleLen {
		return 0, ErrBufferTooShort
	}
	style := string(buf[offset : offset+styleLen])
	offset += styleLen

	switch style {
	case "NTCP2":
		addr.TransportStyle = TransportNTCP2
	case "SSU2":
		addr.TransportStyle = TransportSSU2
	default:
		addr.TransportStyle = TransportUnknown
	}

	// Options size (2 bytes)
	if len(buf) < offset+2 {
		return 0, ErrBufferTooShort
	}
	optSize := int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2

	optEnd := offset + optSize
	if len(buf) < optEnd {
		return 0, ErrBufferTooShort
	}

	// Parse options
	for offset < optEnd {
		if len(buf) < offset+1 {
			break
		}
		keyLen := int(buf[offset])
		offset++
		if len(buf) < offset+keyLen+1 {
			break
		}
		key := string(buf[offset : offset+keyLen])
		offset += keyLen

		if buf[offset] != '=' {
			break
		}
		offset++

		if len(buf) < offset+1 {
			break
		}
		valLen := int(buf[offset])
		offset++
		if len(buf) < offset+valLen+1 {
			break
		}
		val := string(buf[offset : offset+valLen])
		offset += valLen

		if buf[offset] != ';' {
			break
		}
		offset++

		addr.Options[key] = val

		// Parse known options
		switch key {
		case "host":
			addr.Host = net.ParseIP(val)
		case "port":
			if p, err := strconv.Atoi(val); err == nil {
				addr.Port = p
			}
		case "s":
			if data, err := Base64Decode(val); err == nil && len(data) == 32 {
				copy(addr.StaticKey[:], data)
			}
		case "i":
			if data, err := Base64Decode(val); err == nil {
				if len(data) >= 16 {
					copy(addr.IntroKey[:], data)
				}
			}
		case "v":
			if v, err := strconv.Atoi(val); err == nil {
				addr.Version = v
			}
		case "caps":
			for _, c := range val {
				switch c {
				case '4':
					addr.Caps |= AddressCapsV4
				case '6':
					addr.Caps |= AddressCapsV6
				case 'B':
					addr.Caps |= AddressCapsSSUTesting
				case 'C':
					addr.Caps |= AddressCapsSSUIntro
				}
			}
		}
	}

	// Set published based on host presence
	addr.Published = addr.Host != nil && !addr.Host.IsUnspecified()

	return offset, nil
}

// computeFields computes derived fields from properties.
func (ri *RouterInfo) computeFields() {
	// Parse capabilities
	if capsStr, ok := ri.Properties["caps"]; ok {
		for _, c := range capsStr {
			switch c {
			case CapsFlagFloodfill:
				ri.caps |= CapsFloodfill
			case CapsFlagReachable:
				ri.caps |= CapsReachable
			case CapsFlagHidden:
				ri.caps |= CapsHidden
			case CapsFlagUnreachable:
				ri.caps |= CapsUnreachable
			case CapsFlagBandwidthO:
				ri.caps |= CapsHighBandwidth
			case CapsFlagBandwidthP, CapsFlagBandwidthX:
				ri.caps |= CapsExtraBandwidth
			case CapsFlagMediumCongestion:
				ri.congestion = CongestionMedium
			case CapsFlagHighCongestion:
				ri.congestion = CongestionHigh
			case CapsFlagRejectAll:
				ri.congestion = CongestionRejectAll
			}
		}
	}

	// Parse version
	if verStr, ok := ri.Properties[PropertyVersion]; ok {
		ri.version = parseVersion(verStr)
	}

	// Compute supported transports
	for _, addr := range ri.Addresses {
		if addr.IsNTCP2() {
			if addr.IsV4() {
				ri.supportedTransports |= TransportNTCP2V4
			}
			if addr.IsV6() {
				ri.supportedTransports |= TransportNTCP2V6
			}
		}
		if addr.IsSSU2() {
			if addr.IsV4() {
				ri.supportedTransports |= TransportSSU2V4
			}
			if addr.IsV6() {
				ri.supportedTransports |= TransportSSU2V6
			}
		}
	}
}

// parseVersion parses a version string like "0.9.62" to an integer.
func parseVersion(s string) int {
	parts := strings.Split(s, ".")
	version := 0
	for i, p := range parts {
		if v, err := strconv.Atoi(p); err == nil {
			version += v * pow10(2-i)
		}
	}
	return version
}

func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

// GetIdentHash returns the router's IdentHash.
func (ri *RouterInfo) GetIdentHash() IdentHash {
	if !ri.hashComputed {
		ri.identHash = ri.Identity.GetIdentHash()
		ri.hashComputed = true
	}
	return ri.identHash
}

// GetTimestamp returns the timestamp as a time.Time.
func (ri *RouterInfo) GetTimestamp() time.Time {
	return time.UnixMilli(ri.Timestamp)
}

// IsFloodfill returns true if this router is a floodfill.
func (ri *RouterInfo) IsFloodfill() bool {
	return ri.caps&CapsFloodfill != 0
}

// IsReachable returns true if this router is reachable.
func (ri *RouterInfo) IsReachable() bool {
	return ri.caps&CapsReachable != 0
}

// IsHidden returns true if this router is hidden.
func (ri *RouterInfo) IsHidden() bool {
	return ri.caps&CapsHidden != 0
}

// GetCaps returns the capability flags.
func (ri *RouterInfo) GetCaps() Caps {
	return ri.caps
}

// GetCongestion returns the congestion level.
func (ri *RouterInfo) GetCongestion() Congestion {
	return ri.congestion
}

// GetVersion returns the router version as an integer.
func (ri *RouterInfo) GetVersion() int {
	return ri.version
}

// GetVersionString returns the router version string.
func (ri *RouterInfo) GetVersionString() string {
	return ri.Properties[PropertyVersion]
}

// GetSupportedTransports returns the supported transports bitmask.
func (ri *RouterInfo) GetSupportedTransports() SupportedTransports {
	return ri.supportedTransports
}

// GetNTCP2Address returns the first NTCP2 address for the given IP version.
func (ri *RouterInfo) GetNTCP2Address(v4 bool) *RouterAddress {
	for _, addr := range ri.Addresses {
		if addr.IsNTCP2() && ((v4 && addr.IsV4()) || (!v4 && addr.IsV6())) {
			return addr
		}
	}
	return nil
}

// GetSSU2Address returns the first SSU2 address for the given IP version.
func (ri *RouterInfo) GetSSU2Address(v4 bool) *RouterAddress {
	for _, addr := range ri.Addresses {
		if addr.IsSSU2() && ((v4 && addr.IsV4()) || (!v4 && addr.IsV6())) {
			return addr
		}
	}
	return nil
}

// Verify verifies the RouterInfo signature.
func (ri *RouterInfo) Verify() bool {
	if ri.rawBuffer == nil || len(ri.Signature) == 0 {
		return false
	}

	// Data to verify is everything before the signature
	dataLen := len(ri.rawBuffer) - len(ri.Signature)
	if dataLen <= 0 {
		return false
	}

	return ri.Identity.Verify(ri.rawBuffer[:dataLen], ri.Signature)
}

// ToBuffer serializes the RouterInfo to a byte buffer.
func (ri *RouterInfo) ToBuffer() []byte {
	if ri.rawBuffer != nil {
		return ri.rawBuffer
	}
	// TODO: Implement full serialization
	return nil
}
