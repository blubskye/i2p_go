package ssu2

import (
	"encoding/binary"

	"github.com/go-i2p/go-i2p/pkg/crypto"
)

// Packet represents an SSU2 packet.
type Packet struct {
	DestConnID   uint64
	PacketNumber uint32
	Type         MessageType
	Flags        uint8
	Payload      []byte
}

// Header represents an SSU2 packet header.
type Header struct {
	DestConnID   uint64
	PacketNumber uint32
	Type         MessageType
	Flags        uint8
	Version      uint8
	NetID        uint8
}

// ParseHeader parses an SSU2 header from bytes.
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < ShortHeaderSize {
		return nil, ErrInvalidPacket
	}

	h := &Header{
		DestConnID:   binary.BigEndian.Uint64(data[0:8]),
		PacketNumber: binary.BigEndian.Uint32(data[8:12]),
		Type:         MessageType(data[12]),
		Flags:        data[13],
		Version:      data[14],
		NetID:        data[15],
	}

	return h, nil
}

// ToBytes serializes the header to bytes.
func (h *Header) ToBytes() []byte {
	buf := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(buf[0:8], h.DestConnID)
	binary.BigEndian.PutUint32(buf[8:12], h.PacketNumber)
	buf[12] = byte(h.Type)
	buf[13] = h.Flags
	buf[14] = h.Version
	buf[15] = h.NetID
	return buf
}

// Block represents a block within an SSU2 packet.
type Block struct {
	Type BlockType
	Data []byte
}

// NewBlock creates a new block.
func NewBlock(blockType BlockType, data []byte) Block {
	return Block{
		Type: blockType,
		Data: data,
	}
}

// ToBytes serializes the block to bytes.
// Format: Type(1) + Size(2) + Data(Size)
func (b *Block) ToBytes() []byte {
	buf := make([]byte, 3+len(b.Data))
	buf[0] = byte(b.Type)
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(b.Data)))
	copy(buf[3:], b.Data)
	return buf
}

// ParseBlocks parses blocks from a decrypted packet payload.
func ParseBlocks(data []byte) ([]Block, error) {
	var blocks []Block
	offset := 0

	for offset < len(data) {
		if offset+3 > len(data) {
			break // Not enough data for another block header
		}

		blockType := BlockType(data[offset])
		blockSize := int(binary.BigEndian.Uint16(data[offset+1:]))
		offset += 3

		if offset+blockSize > len(data) {
			return nil, ErrInvalidPacket
		}

		blockData := make([]byte, blockSize)
		copy(blockData, data[offset:offset+blockSize])
		offset += blockSize

		blocks = append(blocks, Block{
			Type: blockType,
			Data: blockData,
		})
	}

	return blocks, nil
}

// PacketEncoder handles SSU2 packet encryption.
type PacketEncoder struct {
	key            []byte
	headerKey      []byte
	srcConnID      uint64
	packetNumber   uint32
}

// NewPacketEncoder creates a new packet encoder.
func NewPacketEncoder(key, headerKey []byte, srcConnID uint64) *PacketEncoder {
	return &PacketEncoder{
		key:          key,
		headerKey:    headerKey,
		srcConnID:    srcConnID,
		packetNumber: 0,
	}
}

// EncodePacket encrypts a packet.
func (e *PacketEncoder) EncodePacket(destConnID uint64, msgType MessageType, blocks []Block) ([]byte, error) {
	// Build payload from blocks
	var payloadSize int
	for _, block := range blocks {
		payloadSize += 3 + len(block.Data)
	}

	payload := make([]byte, payloadSize)
	offset := 0
	for _, block := range blocks {
		blockBytes := block.ToBytes()
		copy(payload[offset:], blockBytes)
		offset += len(blockBytes)
	}

	// Create nonce from packet number
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[4:8], e.packetNumber)
	binary.BigEndian.PutUint64(nonce[0:8], destConnID) // Use destConnID in nonce

	// Build header for AAD
	header := &Header{
		DestConnID:   destConnID,
		PacketNumber: e.packetNumber,
		Type:         msgType,
		Flags:        0,
		Version:      2,
		NetID:        2, // I2P mainnet
	}
	headerBytes := header.ToBytes()

	// Encrypt payload with ChaCha20-Poly1305
	encrypted, err := crypto.ChaCha20Poly1305Encrypt(e.key, nonce, payload, headerBytes)
	if err != nil {
		return nil, err
	}

	e.packetNumber++

	// Combine header + encrypted payload
	packet := make([]byte, len(headerBytes)+len(encrypted))
	copy(packet[:len(headerBytes)], headerBytes)
	copy(packet[len(headerBytes):], encrypted)

	return packet, nil
}

// PacketDecoder handles SSU2 packet decryption.
type PacketDecoder struct {
	key         []byte
	headerKey   []byte
	srcConnID   uint64
}

// NewPacketDecoder creates a new packet decoder.
func NewPacketDecoder(key, headerKey []byte, srcConnID uint64) *PacketDecoder {
	return &PacketDecoder{
		key:       key,
		headerKey: headerKey,
		srcConnID: srcConnID,
	}
}

// DecodePacket decrypts a packet.
func (d *PacketDecoder) DecodePacket(data []byte) (*Header, []Block, error) {
	if len(data) < ShortHeaderSize+16 { // Header + minimum MAC
		return nil, nil, ErrInvalidPacket
	}

	// Parse header
	header, err := ParseHeader(data)
	if err != nil {
		return nil, nil, err
	}

	headerBytes := data[:ShortHeaderSize]
	encrypted := data[ShortHeaderSize:]

	// Create nonce from packet number
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[4:8], header.PacketNumber)
	binary.BigEndian.PutUint64(nonce[0:8], header.DestConnID)

	// Decrypt with ChaCha20-Poly1305
	payload, err := crypto.ChaCha20Poly1305Decrypt(d.key, nonce, encrypted, headerBytes)
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	// Parse blocks
	blocks, err := ParseBlocks(payload)
	if err != nil {
		return nil, nil, err
	}

	return header, blocks, nil
}

// DateTimeBlock creates a DateTime block.
func DateTimeBlock(timestamp uint32) Block {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, timestamp)
	return NewBlock(BlockDateTime, data)
}

// OptionsBlock creates an Options block.
func OptionsBlock() Block {
	return NewBlock(BlockOptions, nil)
}

// RouterInfoBlock creates a RouterInfo block.
func RouterInfoBlock(routerInfo []byte, flood bool) Block {
	data := make([]byte, 1+len(routerInfo))
	if flood {
		data[0] = 0x01
	}
	copy(data[1:], routerInfo)
	return NewBlock(BlockRouterInfo, data)
}

// I2NPMessageBlock creates an I2NP message block.
func I2NPMessageBlock(message []byte) Block {
	return NewBlock(BlockI2NPMessage, message)
}

// FirstFragmentBlock creates a first fragment block.
func FirstFragmentBlock(msgID uint32, totalSize uint16, fragment []byte) Block {
	data := make([]byte, 6+len(fragment))
	binary.BigEndian.PutUint32(data[0:4], msgID)
	binary.BigEndian.PutUint16(data[4:6], totalSize)
	copy(data[6:], fragment)
	return NewBlock(BlockFirstFragment, data)
}

// FollowOnFragmentBlock creates a follow-on fragment block.
func FollowOnFragmentBlock(msgID uint32, fragmentNum uint8, isLast bool, fragment []byte) Block {
	data := make([]byte, 5+len(fragment))
	flags := fragmentNum
	if isLast {
		flags |= 0x80
	}
	data[0] = flags
	binary.BigEndian.PutUint32(data[1:5], msgID)
	copy(data[5:], fragment)
	return NewBlock(BlockFollowOnFragment, data)
}

// TerminationBlock creates a Termination block.
func TerminationBlock(reason TerminationReason) Block {
	data := make([]byte, 9)
	data[8] = byte(reason)
	return NewBlock(BlockTermination, data)
}

// ACKBlock creates an ACK block.
func ACKBlock(ackThrough uint32, ranges [][2]uint32) Block {
	// ACK format: AckThrough(4) + ACK count(1) + Ranges...
	data := make([]byte, 5+len(ranges)*2)
	binary.BigEndian.PutUint32(data[0:4], ackThrough)
	data[4] = byte(len(ranges))
	offset := 5
	for _, r := range ranges {
		data[offset] = byte(r[0])   // Ack count
		data[offset+1] = byte(r[1]) // Nack count
		offset += 2
	}
	return NewBlock(BlockACK, data[:offset])
}

// AddressBlock creates an Address block.
func AddressBlock(ip []byte, port uint16) Block {
	data := make([]byte, len(ip)+2)
	copy(data, ip)
	binary.BigEndian.PutUint16(data[len(ip):], port)
	return NewBlock(BlockAddress, data)
}

// NewTokenBlock creates a NewToken block.
func NewTokenBlock(token []byte, expiration uint32) Block {
	data := make([]byte, 4+len(token))
	binary.BigEndian.PutUint32(data[0:4], expiration)
	copy(data[4:], token)
	return NewBlock(BlockNewToken, data)
}

// PaddingBlock creates a Padding block.
func PaddingBlock(size int) Block {
	return NewBlock(BlockPadding, make([]byte, size))
}

// ParseACKBlock parses an ACK block.
func ParseACKBlock(data []byte) (ackThrough uint32, ranges [][2]uint32, err error) {
	if len(data) < 5 {
		return 0, nil, ErrInvalidPacket
	}

	ackThrough = binary.BigEndian.Uint32(data[0:4])
	count := int(data[4])

	if len(data) < 5+count*2 {
		return 0, nil, ErrInvalidPacket
	}

	ranges = make([][2]uint32, count)
	offset := 5
	for i := 0; i < count; i++ {
		ranges[i][0] = uint32(data[offset])
		ranges[i][1] = uint32(data[offset+1])
		offset += 2
	}

	return ackThrough, ranges, nil
}

// ParseFirstFragmentBlock parses a first fragment block.
func ParseFirstFragmentBlock(data []byte) (msgID uint32, totalSize uint16, fragment []byte, err error) {
	if len(data) < 6 {
		return 0, 0, nil, ErrInvalidPacket
	}

	msgID = binary.BigEndian.Uint32(data[0:4])
	totalSize = binary.BigEndian.Uint16(data[4:6])
	fragment = data[6:]
	return msgID, totalSize, fragment, nil
}

// ParseFollowOnFragmentBlock parses a follow-on fragment block.
func ParseFollowOnFragmentBlock(data []byte) (msgID uint32, fragmentNum uint8, isLast bool, fragment []byte, err error) {
	if len(data) < 5 {
		return 0, 0, false, nil, ErrInvalidPacket
	}

	flags := data[0]
	fragmentNum = flags & 0x7F
	isLast = (flags & 0x80) != 0
	msgID = binary.BigEndian.Uint32(data[1:5])
	fragment = data[5:]
	return msgID, fragmentNum, isLast, fragment, nil
}
