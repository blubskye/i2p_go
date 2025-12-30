package ntcp2

import (
	"encoding/binary"

	"github.com/go-i2p/go-i2p/pkg/crypto"
)

// Frame represents an NTCP2 data frame.
type Frame struct {
	Blocks []Block
}

// NewFrame creates a new frame with the given blocks.
func NewFrame(blocks ...Block) *Frame {
	return &Frame{
		Blocks: blocks,
	}
}

// Block represents a block within an NTCP2 frame.
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

// ToBytes serializes the frame to bytes (unencrypted payload).
func (f *Frame) ToBytes() []byte {
	var size int
	for _, block := range f.Blocks {
		size += 3 + len(block.Data)
	}

	buf := make([]byte, size)
	offset := 0

	for _, block := range f.Blocks {
		blockBytes := block.ToBytes()
		copy(buf[offset:], blockBytes)
		offset += len(blockBytes)
	}

	return buf
}

// ParseBlocks parses blocks from a decrypted frame payload.
func ParseBlocks(data []byte) ([]Block, error) {
	var blocks []Block
	offset := 0

	for offset < len(data) {
		if offset+3 > len(data) {
			return nil, ErrInvalidMessage
		}

		blockType := BlockType(data[offset])
		blockSize := int(binary.BigEndian.Uint16(data[offset+1:]))
		offset += 3

		if offset+blockSize > len(data) {
			return nil, ErrInvalidMessage
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

// FrameEncoder handles NTCP2 frame encryption.
type FrameEncoder struct {
	key            []byte
	sipKey         []byte
	sequenceNumber uint64
}

// NewFrameEncoder creates a new frame encoder.
func NewFrameEncoder(key, sipKey []byte) *FrameEncoder {
	return &FrameEncoder{
		key:            key,
		sipKey:         sipKey,
		sequenceNumber: 0,
	}
}

// EncodeFrame encrypts a frame and returns length prefix + encrypted data + MAC.
func (e *FrameEncoder) EncodeFrame(payload []byte) ([]byte, error) {
	if len(payload) > UnencryptedFrameMaxSize {
		return nil, ErrFrameTooLarge
	}

	// Create nonce from sequence number
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], e.sequenceNumber)
	e.sequenceNumber++

	// Encrypt payload with ChaCha20-Poly1305
	encrypted, err := crypto.ChaCha20Poly1305Encrypt(e.key, nonce, payload, nil)
	if err != nil {
		return nil, err
	}

	// Obfuscate length with SipHash
	frameLen := uint16(len(encrypted))
	iv := binary.LittleEndian.Uint64(nonce[4:])
	obfuscatedLen := crypto.NTCP2LengthObfuscate(e.sipKey, iv, frameLen)

	// Combine length + encrypted payload
	result := make([]byte, 2+len(encrypted))
	binary.BigEndian.PutUint16(result[0:2], obfuscatedLen)
	copy(result[2:], encrypted)

	return result, nil
}

// FrameDecoder handles NTCP2 frame decryption.
type FrameDecoder struct {
	key            []byte
	sipKey         []byte
	sequenceNumber uint64
}

// NewFrameDecoder creates a new frame decoder.
func NewFrameDecoder(key, sipKey []byte) *FrameDecoder {
	return &FrameDecoder{
		key:            key,
		sipKey:         sipKey,
		sequenceNumber: 0,
	}
}

// DecodeLength decrypts and returns the frame length from the 2-byte header.
func (d *FrameDecoder) DecodeLength(lenBuf []byte) uint16 {
	// Create nonce from sequence number
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], d.sequenceNumber)

	// De-obfuscate length with SipHash
	obfuscatedLen := binary.BigEndian.Uint16(lenBuf)
	iv := binary.LittleEndian.Uint64(nonce[4:])
	length := crypto.NTCP2LengthDeobfuscate(d.sipKey, iv, obfuscatedLen)

	return length
}

// DecodeFrame decrypts a frame (without the length prefix).
func (d *FrameDecoder) DecodeFrame(encrypted []byte) ([]byte, error) {
	// Create nonce from sequence number
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], d.sequenceNumber)
	d.sequenceNumber++

	// Decrypt with ChaCha20-Poly1305
	payload, err := crypto.ChaCha20Poly1305Decrypt(d.key, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return payload, nil
}

// DateTimeBlock creates a DateTime block with the current timestamp.
func DateTimeBlock(timestamp uint32) Block {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, timestamp)
	return NewBlock(BlockDateTime, data)
}

// OptionsBlock creates an Options block.
func OptionsBlock(opts *SessionOptions) Block {
	// Options block is variable length, but we'll use basic format
	// For now, return empty options (negotiated via defaults)
	return NewBlock(BlockOptions, nil)
}

// RouterInfoBlock creates a RouterInfo block.
func RouterInfoBlock(routerInfo []byte, flood bool) Block {
	// Format: Flags(1) + RouterInfo
	data := make([]byte, 1+len(routerInfo))
	if flood {
		data[0] = RouterInfoFlagRequestFlood
	}
	copy(data[1:], routerInfo)
	return NewBlock(BlockRouterInfo, data)
}

// I2NPMessageBlock creates an I2NP message block.
func I2NPMessageBlock(message []byte) Block {
	return NewBlock(BlockI2NPMessage, message)
}

// TerminationBlock creates a Termination block.
func TerminationBlock(reason TerminationReason, validFrames uint64) Block {
	data := make([]byte, 9)
	binary.BigEndian.PutUint64(data[0:8], validFrames)
	data[8] = byte(reason)
	return NewBlock(BlockTermination, data)
}

// PaddingBlock creates a Padding block of the specified size.
func PaddingBlock(size int) Block {
	return NewBlock(BlockPadding, make([]byte, size))
}

// ParseDateTimeBlock parses a DateTime block.
func ParseDateTimeBlock(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, ErrInvalidMessage
	}
	return binary.BigEndian.Uint32(data), nil
}

// ParseTerminationBlock parses a Termination block.
func ParseTerminationBlock(data []byte) (TerminationReason, uint64, error) {
	if len(data) < 9 {
		return 0, 0, ErrInvalidMessage
	}
	validFrames := binary.BigEndian.Uint64(data[0:8])
	reason := TerminationReason(data[8])
	return reason, validFrames, nil
}

// ParseRouterInfoBlock parses a RouterInfo block.
func ParseRouterInfoBlock(data []byte) ([]byte, bool, error) {
	if len(data) < 1 {
		return nil, false, ErrInvalidMessage
	}
	flags := data[0]
	flood := (flags & RouterInfoFlagRequestFlood) != 0
	routerInfo := data[1:]
	return routerInfo, flood, nil
}
