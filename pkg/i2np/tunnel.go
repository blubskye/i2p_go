package i2np

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Tunnel message constants
const (
	TunnelDataSize        = 1028 // TunnelID (4) + Data (1024)
	TunnelDataPayloadSize = 1024

	TunnelGatewayHeaderSize = 6 // TunnelID (4) + Length (2)

	TunnelBuildRecordSize      = 528
	ShortTunnelBuildRecordSize = 218
	NumTunnelBuildRecords      = 8
)

// Tunnel build record flags
const (
	TunnelBuildRecordGatewayFlag  = 0x80
	TunnelBuildRecordEndpointFlag = 0x40
)

// TunnelData carries data through a tunnel.
type TunnelData struct {
	TunnelID uint32
	Data     [TunnelDataPayloadSize]byte
}

// NewTunnelData creates a new TunnelData message.
func NewTunnelData(tunnelID uint32, payload []byte) *TunnelData {
	td := &TunnelData{
		TunnelID: tunnelID,
	}
	copy(td.Data[:], payload)
	return td
}

// ParseTunnelData parses a TunnelData from payload bytes.
func ParseTunnelData(payload []byte) (*TunnelData, error) {
	if len(payload) < TunnelDataSize {
		return nil, ErrMessageTooShort
	}

	td := &TunnelData{
		TunnelID: binary.BigEndian.Uint32(payload[0:4]),
	}
	copy(td.Data[:], payload[4:TunnelDataSize])

	return td, nil
}

// Type returns TypeTunnelData.
func (t *TunnelData) Type() MessageType {
	return TypeTunnelData
}

// GetMsgID returns 0 (TunnelData doesn't have individual message IDs).
func (t *TunnelData) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *TunnelData) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the TunnelData to payload bytes.
func (t *TunnelData) ToPayload() []byte {
	buf := make([]byte, TunnelDataSize)
	binary.BigEndian.PutUint32(buf[0:4], t.TunnelID)
	copy(buf[4:], t.Data[:])
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *TunnelData) ToBytes() []byte {
	return NewRawMessage(TypeTunnelData, t.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (t *TunnelData) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeTunnelData, t.ToPayload())
}

// TunnelGateway wraps an I2NP message for tunnel delivery.
type TunnelGateway struct {
	TunnelID uint32
	Data     []byte // Enclosed I2NP message
}

// NewTunnelGateway creates a new TunnelGateway message.
func NewTunnelGateway(tunnelID uint32, enclosedMessage []byte) *TunnelGateway {
	return &TunnelGateway{
		TunnelID: tunnelID,
		Data:     enclosedMessage,
	}
}

// ParseTunnelGateway parses a TunnelGateway from payload bytes.
func ParseTunnelGateway(payload []byte) (*TunnelGateway, error) {
	if len(payload) < TunnelGatewayHeaderSize {
		return nil, ErrMessageTooShort
	}

	tg := &TunnelGateway{
		TunnelID: binary.BigEndian.Uint32(payload[0:4]),
	}
	length := binary.BigEndian.Uint16(payload[4:6])

	if len(payload) < TunnelGatewayHeaderSize+int(length) {
		return nil, ErrMessageTooShort
	}

	tg.Data = make([]byte, length)
	copy(tg.Data, payload[TunnelGatewayHeaderSize:TunnelGatewayHeaderSize+int(length)])

	return tg, nil
}

// Type returns TypeTunnelGateway.
func (t *TunnelGateway) Type() MessageType {
	return TypeTunnelGateway
}

// GetMsgID returns 0.
func (t *TunnelGateway) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *TunnelGateway) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the TunnelGateway to payload bytes.
func (t *TunnelGateway) ToPayload() []byte {
	buf := make([]byte, TunnelGatewayHeaderSize+len(t.Data))
	binary.BigEndian.PutUint32(buf[0:4], t.TunnelID)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(t.Data)))
	copy(buf[TunnelGatewayHeaderSize:], t.Data)
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *TunnelGateway) ToBytes() []byte {
	return NewRawMessage(TypeTunnelGateway, t.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (t *TunnelGateway) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeTunnelGateway, t.ToPayload())
}

// TunnelBuildRecord represents a single record in a tunnel build request.
type TunnelBuildRecord struct {
	ToPeer        data.Hash // First 16 bytes are the encrypted AES block
	EncryptedData []byte    // 512 bytes of encrypted data (for standard) or 202 bytes (for short)
}

// TunnelBuild is a request to build a tunnel.
type TunnelBuild struct {
	Records []*TunnelBuildRecord
}

// NewTunnelBuild creates a new TunnelBuild message.
func NewTunnelBuild(records []*TunnelBuildRecord) *TunnelBuild {
	return &TunnelBuild{
		Records: records,
	}
}

// ParseTunnelBuild parses a TunnelBuild from payload bytes.
func ParseTunnelBuild(payload []byte) (*TunnelBuild, error) {
	expectedSize := NumTunnelBuildRecords * TunnelBuildRecordSize
	if len(payload) < expectedSize {
		return nil, ErrMessageTooShort
	}

	tb := &TunnelBuild{
		Records: make([]*TunnelBuildRecord, NumTunnelBuildRecords),
	}

	for i := 0; i < NumTunnelBuildRecords; i++ {
		offset := i * TunnelBuildRecordSize
		record := &TunnelBuildRecord{}
		copy(record.ToPeer[:], payload[offset:offset+16])
		record.EncryptedData = make([]byte, TunnelBuildRecordSize-16)
		copy(record.EncryptedData, payload[offset+16:offset+TunnelBuildRecordSize])
		tb.Records[i] = record
	}

	return tb, nil
}

// Type returns TypeTunnelBuild.
func (t *TunnelBuild) Type() MessageType {
	return TypeTunnelBuild
}

// GetMsgID returns 0.
func (t *TunnelBuild) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *TunnelBuild) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the TunnelBuild to payload bytes.
func (t *TunnelBuild) ToPayload() []byte {
	buf := make([]byte, NumTunnelBuildRecords*TunnelBuildRecordSize)
	for i, record := range t.Records {
		offset := i * TunnelBuildRecordSize
		copy(buf[offset:], record.ToPeer[:16])
		copy(buf[offset+16:], record.EncryptedData)
	}
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *TunnelBuild) ToBytes() []byte {
	return NewRawMessage(TypeTunnelBuild, t.ToPayload()).ToBytes()
}

// VariableTunnelBuild is a tunnel build with variable number of records.
type VariableTunnelBuild struct {
	Records []*TunnelBuildRecord
}

// NewVariableTunnelBuild creates a new VariableTunnelBuild message.
func NewVariableTunnelBuild(records []*TunnelBuildRecord) *VariableTunnelBuild {
	return &VariableTunnelBuild{
		Records: records,
	}
}

// ParseVariableTunnelBuild parses a VariableTunnelBuild from payload bytes.
func ParseVariableTunnelBuild(payload []byte) (*VariableTunnelBuild, error) {
	if len(payload) < 1 {
		return nil, ErrMessageTooShort
	}

	numRecords := int(payload[0])
	expectedSize := 1 + numRecords*TunnelBuildRecordSize
	if len(payload) < expectedSize {
		return nil, ErrMessageTooShort
	}

	vtb := &VariableTunnelBuild{
		Records: make([]*TunnelBuildRecord, numRecords),
	}

	for i := 0; i < numRecords; i++ {
		offset := 1 + i*TunnelBuildRecordSize
		record := &TunnelBuildRecord{}
		copy(record.ToPeer[:], payload[offset:offset+16])
		record.EncryptedData = make([]byte, TunnelBuildRecordSize-16)
		copy(record.EncryptedData, payload[offset+16:offset+TunnelBuildRecordSize])
		vtb.Records[i] = record
	}

	return vtb, nil
}

// Type returns TypeVariableTunnelBuild.
func (t *VariableTunnelBuild) Type() MessageType {
	return TypeVariableTunnelBuild
}

// GetMsgID returns 0.
func (t *VariableTunnelBuild) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *VariableTunnelBuild) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the VariableTunnelBuild to payload bytes.
func (t *VariableTunnelBuild) ToPayload() []byte {
	buf := make([]byte, 1+len(t.Records)*TunnelBuildRecordSize)
	buf[0] = byte(len(t.Records))
	for i, record := range t.Records {
		offset := 1 + i*TunnelBuildRecordSize
		copy(buf[offset:], record.ToPeer[:16])
		copy(buf[offset+16:], record.EncryptedData)
	}
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *VariableTunnelBuild) ToBytes() []byte {
	return NewRawMessage(TypeVariableTunnelBuild, t.ToPayload()).ToBytes()
}

// ToRawMessage converts to a RawMessage.
func (t *VariableTunnelBuild) ToRawMessage() *RawMessage {
	return NewRawMessage(TypeVariableTunnelBuild, t.ToPayload())
}

// ShortTunnelBuild is a modern tunnel build with smaller records.
type ShortTunnelBuild struct {
	Records []*TunnelBuildRecord
}

// NewShortTunnelBuild creates a new ShortTunnelBuild message.
func NewShortTunnelBuild(records []*TunnelBuildRecord) *ShortTunnelBuild {
	return &ShortTunnelBuild{
		Records: records,
	}
}

// ParseShortTunnelBuild parses a ShortTunnelBuild from payload bytes.
func ParseShortTunnelBuild(payload []byte) (*ShortTunnelBuild, error) {
	if len(payload) < 1 {
		return nil, ErrMessageTooShort
	}

	numRecords := int(payload[0])
	expectedSize := 1 + numRecords*ShortTunnelBuildRecordSize
	if len(payload) < expectedSize {
		return nil, ErrMessageTooShort
	}

	stb := &ShortTunnelBuild{
		Records: make([]*TunnelBuildRecord, numRecords),
	}

	for i := 0; i < numRecords; i++ {
		offset := 1 + i*ShortTunnelBuildRecordSize
		record := &TunnelBuildRecord{}
		copy(record.ToPeer[:], payload[offset:offset+16])
		record.EncryptedData = make([]byte, ShortTunnelBuildRecordSize-16)
		copy(record.EncryptedData, payload[offset+16:offset+ShortTunnelBuildRecordSize])
		stb.Records[i] = record
	}

	return stb, nil
}

// Type returns TypeShortTunnelBuild.
func (t *ShortTunnelBuild) Type() MessageType {
	return TypeShortTunnelBuild
}

// GetMsgID returns 0.
func (t *ShortTunnelBuild) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *ShortTunnelBuild) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the ShortTunnelBuild to payload bytes.
func (t *ShortTunnelBuild) ToPayload() []byte {
	buf := make([]byte, 1+len(t.Records)*ShortTunnelBuildRecordSize)
	buf[0] = byte(len(t.Records))
	for i, record := range t.Records {
		offset := 1 + i*ShortTunnelBuildRecordSize
		copy(buf[offset:], record.ToPeer[:16])
		copy(buf[offset+16:], record.EncryptedData)
	}
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *ShortTunnelBuild) ToBytes() []byte {
	return NewRawMessage(TypeShortTunnelBuild, t.ToPayload()).ToBytes()
}

// TunnelBuildReplyRecord represents a reply record from a hop.
type TunnelBuildReplyRecord struct {
	EncryptedData []byte // Encrypted reply data
}

// TunnelBuildReply is the reply to a TunnelBuild request.
type TunnelBuildReply struct {
	Records []*TunnelBuildReplyRecord
}

// NewTunnelBuildReply creates a new TunnelBuildReply message.
func NewTunnelBuildReply(records []*TunnelBuildReplyRecord) *TunnelBuildReply {
	return &TunnelBuildReply{
		Records: records,
	}
}

// ParseTunnelBuildReply parses a TunnelBuildReply from payload bytes.
func ParseTunnelBuildReply(payload []byte) (*TunnelBuildReply, error) {
	expectedSize := NumTunnelBuildRecords * TunnelBuildRecordSize
	if len(payload) < expectedSize {
		return nil, ErrMessageTooShort
	}

	tbr := &TunnelBuildReply{
		Records: make([]*TunnelBuildReplyRecord, NumTunnelBuildRecords),
	}

	for i := 0; i < NumTunnelBuildRecords; i++ {
		offset := i * TunnelBuildRecordSize
		record := &TunnelBuildReplyRecord{
			EncryptedData: make([]byte, TunnelBuildRecordSize),
		}
		copy(record.EncryptedData, payload[offset:offset+TunnelBuildRecordSize])
		tbr.Records[i] = record
	}

	return tbr, nil
}

// Type returns TypeTunnelBuildReply.
func (t *TunnelBuildReply) Type() MessageType {
	return TypeTunnelBuildReply
}

// GetMsgID returns 0.
func (t *TunnelBuildReply) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *TunnelBuildReply) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the TunnelBuildReply to payload bytes.
func (t *TunnelBuildReply) ToPayload() []byte {
	buf := make([]byte, NumTunnelBuildRecords*TunnelBuildRecordSize)
	for i, record := range t.Records {
		offset := i * TunnelBuildRecordSize
		copy(buf[offset:], record.EncryptedData)
	}
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *TunnelBuildReply) ToBytes() []byte {
	return NewRawMessage(TypeTunnelBuildReply, t.ToPayload()).ToBytes()
}

// VariableTunnelBuildReply is the reply to a VariableTunnelBuild request.
type VariableTunnelBuildReply struct {
	Records []*TunnelBuildReplyRecord
}

// NewVariableTunnelBuildReply creates a new VariableTunnelBuildReply message.
func NewVariableTunnelBuildReply(records []*TunnelBuildReplyRecord) *VariableTunnelBuildReply {
	return &VariableTunnelBuildReply{
		Records: records,
	}
}

// ParseVariableTunnelBuildReply parses a VariableTunnelBuildReply from payload bytes.
func ParseVariableTunnelBuildReply(payload []byte) (*VariableTunnelBuildReply, error) {
	if len(payload) < 1 {
		return nil, ErrMessageTooShort
	}

	numRecords := int(payload[0])
	expectedSize := 1 + numRecords*TunnelBuildRecordSize
	if len(payload) < expectedSize {
		return nil, ErrMessageTooShort
	}

	vtbr := &VariableTunnelBuildReply{
		Records: make([]*TunnelBuildReplyRecord, numRecords),
	}

	for i := 0; i < numRecords; i++ {
		offset := 1 + i*TunnelBuildRecordSize
		record := &TunnelBuildReplyRecord{
			EncryptedData: make([]byte, TunnelBuildRecordSize),
		}
		copy(record.EncryptedData, payload[offset:offset+TunnelBuildRecordSize])
		vtbr.Records[i] = record
	}

	return vtbr, nil
}

// Type returns TypeVariableTunnelBuildReply.
func (t *VariableTunnelBuildReply) Type() MessageType {
	return TypeVariableTunnelBuildReply
}

// GetMsgID returns 0.
func (t *VariableTunnelBuildReply) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *VariableTunnelBuildReply) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the VariableTunnelBuildReply to payload bytes.
func (t *VariableTunnelBuildReply) ToPayload() []byte {
	buf := make([]byte, 1+len(t.Records)*TunnelBuildRecordSize)
	buf[0] = byte(len(t.Records))
	for i, record := range t.Records {
		offset := 1 + i*TunnelBuildRecordSize
		copy(buf[offset:], record.EncryptedData)
	}
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *VariableTunnelBuildReply) ToBytes() []byte {
	return NewRawMessage(TypeVariableTunnelBuildReply, t.ToPayload()).ToBytes()
}

// ShortTunnelBuildReply is the reply to a ShortTunnelBuild request.
type ShortTunnelBuildReply struct {
	Records []*TunnelBuildReplyRecord
}

// NewShortTunnelBuildReply creates a new ShortTunnelBuildReply message.
func NewShortTunnelBuildReply(records []*TunnelBuildReplyRecord) *ShortTunnelBuildReply {
	return &ShortTunnelBuildReply{
		Records: records,
	}
}

// ParseShortTunnelBuildReply parses a ShortTunnelBuildReply from payload bytes.
func ParseShortTunnelBuildReply(payload []byte) (*ShortTunnelBuildReply, error) {
	if len(payload) < 1 {
		return nil, ErrMessageTooShort
	}

	numRecords := int(payload[0])
	expectedSize := 1 + numRecords*ShortTunnelBuildRecordSize
	if len(payload) < expectedSize {
		return nil, ErrMessageTooShort
	}

	stbr := &ShortTunnelBuildReply{
		Records: make([]*TunnelBuildReplyRecord, numRecords),
	}

	for i := 0; i < numRecords; i++ {
		offset := 1 + i*ShortTunnelBuildRecordSize
		record := &TunnelBuildReplyRecord{
			EncryptedData: make([]byte, ShortTunnelBuildRecordSize),
		}
		copy(record.EncryptedData, payload[offset:offset+ShortTunnelBuildRecordSize])
		stbr.Records[i] = record
	}

	return stbr, nil
}

// Type returns TypeShortTunnelBuildReply.
func (t *ShortTunnelBuildReply) Type() MessageType {
	return TypeShortTunnelBuildReply
}

// GetMsgID returns 0.
func (t *ShortTunnelBuildReply) GetMsgID() uint32 {
	return 0
}

// GetExpiration returns current time.
func (t *ShortTunnelBuildReply) GetExpiration() time.Time {
	return time.Now()
}

// ToPayload serializes the ShortTunnelBuildReply to payload bytes.
func (t *ShortTunnelBuildReply) ToPayload() []byte {
	buf := make([]byte, 1+len(t.Records)*ShortTunnelBuildRecordSize)
	buf[0] = byte(len(t.Records))
	for i, record := range t.Records {
		offset := 1 + i*ShortTunnelBuildRecordSize
		copy(buf[offset:], record.EncryptedData)
	}
	return buf
}

// ToBytes serializes to a complete I2NP message.
func (t *ShortTunnelBuildReply) ToBytes() []byte {
	return NewRawMessage(TypeShortTunnelBuildReply, t.ToPayload()).ToBytes()
}
