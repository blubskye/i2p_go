package streaming

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Stream implements a TCP-like stream over I2P.
type Stream struct {
	mu sync.Mutex

	// Stream identifiers
	sendStreamID    StreamID
	receiveStreamID StreamID

	// Connection state
	state       int
	localDest   *data.Destination
	remoteDest  *data.Destination

	// Sequence numbers
	sendSeqNum    uint32
	recvSeqNum    uint32
	ackThrough    uint32
	lastAckSent   uint32

	// Window management
	sendWindow     int
	recvWindow     int
	congestionWnd  int
	slowStartThresh int

	// RTT estimation
	rtt           time.Duration
	rttVar        time.Duration

	// Buffers
	sendQueue     []*Packet
	recvQueue     []*Packet
	readBuffer    []byte
	readPos       int
	readEnd       int

	// Unordered receive buffer for out-of-order packets
	outOfOrder    map[uint32][]byte

	// Pending retransmissions
	unacked       map[uint32]*unackedPacket

	// Message sender function
	sendFunc      func(dest data.Hash, payload []byte) error

	// Timers
	retransmitTimer *time.Timer
	keepaliveTimer  *time.Timer

	// Channels
	readReady     chan struct{}
	writeReady    chan struct{}
	closed        chan struct{}

	// Stats
	bytesSent     int64
	bytesReceived int64
	packetsSent   int64
	packetsReceived int64
	retransmits   int64

	// Read/write deadlines
	readDeadline  time.Time
	writeDeadline time.Time
}

// unackedPacket tracks a sent packet waiting for acknowledgment.
type unackedPacket struct {
	packet    *Packet
	sentAt    time.Time
	retries   int
}

// NewStream creates a new stream for outbound connections.
func NewStream(localDest *data.Destination, sendFunc func(data.Hash, []byte) error) *Stream {
	s := &Stream{
		sendStreamID:    generateStreamID(),
		state:           StateInit,
		localDest:       localDest,
		sendWindow:      DefaultWindowSize,
		recvWindow:      DefaultWindowSize,
		congestionWnd:   2,
		slowStartThresh: MaxWindowSize / 2,
		rtt:             DefaultRTT,
		rttVar:          DefaultRTT / 2,
		readBuffer:      make([]byte, ReceiveBufferSize),
		outOfOrder:      make(map[uint32][]byte),
		unacked:         make(map[uint32]*unackedPacket),
		sendFunc:        sendFunc,
		readReady:       make(chan struct{}, 1),
		writeReady:      make(chan struct{}, 1),
		closed:          make(chan struct{}),
	}
	return s
}

// NewInboundStream creates a new stream for an incoming connection.
func NewInboundStream(localDest *data.Destination, remoteDest *data.Destination,
	recvStreamID StreamID, sendFunc func(data.Hash, []byte) error) *Stream {
	s := NewStream(localDest, sendFunc)
	s.remoteDest = remoteDest
	s.receiveStreamID = recvStreamID
	s.state = StateSynSent // Will transition to Established after SYN-ACK
	return s
}

// Connect initiates a connection to a remote destination.
func (s *Stream) Connect(dest *data.Destination) error {
	s.mu.Lock()
	if s.state != StateInit {
		s.mu.Unlock()
		return ErrNotEstablished
	}

	s.remoteDest = dest
	s.state = StateSynSent
	s.mu.Unlock()

	// Build SYN options
	options := s.buildSYNOptions()
	synPacket := NewSYNPacket(s.sendStreamID, options)

	// Send SYN
	if err := s.sendPacket(synPacket); err != nil {
		return err
	}

	// Wait for SYN-ACK
	select {
	case <-s.writeReady:
		return nil
	case <-time.After(ConnectTimeout):
		s.mu.Lock()
		s.state = StateClosed
		s.mu.Unlock()
		return ErrConnectTimeout
	case <-s.closed:
		return ErrStreamClosed
	}
}

// Read reads data from the stream.
func (s *Stream) Read(b []byte) (int, error) {
	for {
		s.mu.Lock()
		if s.state == StateClosed || s.state == StateClosing {
			// Check if there's still data in the buffer
			if s.readEnd > s.readPos {
				n := copy(b, s.readBuffer[s.readPos:s.readEnd])
				s.readPos += n
				s.mu.Unlock()
				return n, nil
			}
			s.mu.Unlock()
			return 0, io.EOF
		}

		// Check for available data
		if s.readEnd > s.readPos {
			n := copy(b, s.readBuffer[s.readPos:s.readEnd])
			s.readPos += n

			// Reset buffer if empty
			if s.readPos == s.readEnd {
				s.readPos = 0
				s.readEnd = 0
			}

			s.mu.Unlock()
			return n, nil
		}
		s.mu.Unlock()

		// Wait for data or timeout
		deadline := s.readDeadline
		if deadline.IsZero() {
			select {
			case <-s.readReady:
				continue
			case <-s.closed:
				return 0, io.EOF
			}
		} else {
			timeout := time.Until(deadline)
			if timeout <= 0 {
				return 0, &timeoutError{}
			}
			select {
			case <-s.readReady:
				continue
			case <-time.After(timeout):
				return 0, &timeoutError{}
			case <-s.closed:
				return 0, io.EOF
			}
		}
	}
}

// Write writes data to the stream.
func (s *Stream) Write(b []byte) (int, error) {
	s.mu.Lock()
	if s.state != StateEstablished {
		s.mu.Unlock()
		return 0, ErrNotEstablished
	}
	s.mu.Unlock()

	written := 0
	remaining := b

	for len(remaining) > 0 {
		// Check window availability
		s.mu.Lock()
		if len(s.unacked) >= s.congestionWnd {
			s.mu.Unlock()
			// Wait for ACKs
			deadline := s.writeDeadline
			if deadline.IsZero() {
				select {
				case <-s.writeReady:
					continue
				case <-s.closed:
					return written, ErrStreamClosed
				}
			} else {
				timeout := time.Until(deadline)
				if timeout <= 0 {
					return written, &timeoutError{}
				}
				select {
				case <-s.writeReady:
					continue
				case <-time.After(timeout):
					return written, &timeoutError{}
				case <-s.closed:
					return written, ErrStreamClosed
				}
			}
		}

		// Determine chunk size
		chunkSize := DefaultMTU - PacketHeaderSize
		if len(remaining) < chunkSize {
			chunkSize = len(remaining)
		}

		// Create and send packet
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		pkt := NewDataPacket(s.sendStreamID, s.receiveStreamID, s.sendSeqNum, s.ackThrough, chunk)
		s.sendSeqNum++
		s.mu.Unlock()

		if err := s.sendPacket(pkt); err != nil {
			return written, err
		}

		written += chunkSize

		s.mu.Lock()
		s.bytesSent += int64(chunkSize)
		s.mu.Unlock()
	}

	return written, nil
}

// Close closes the stream.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.state == StateClosed {
		s.mu.Unlock()
		return nil
	}

	if s.state == StateEstablished {
		s.state = StateClosing
		s.mu.Unlock()

		// Send close packet
		closePacket := NewClosePacket(s.sendStreamID, s.receiveStreamID, s.sendSeqNum, s.ackThrough)
		s.sendPacket(closePacket)

		// Wait briefly for ACK
		select {
		case <-time.After(2 * time.Second):
		case <-s.closed:
		}

		s.mu.Lock()
	}

	s.state = StateClosed
	close(s.closed)
	s.mu.Unlock()

	return nil
}

// LocalAddr returns the local address.
func (s *Stream) LocalAddr() net.Addr {
	return &streamAddr{dest: s.localDest}
}

// RemoteAddr returns the remote address.
func (s *Stream) RemoteAddr() net.Addr {
	return &streamAddr{dest: s.remoteDest}
}

// SetDeadline sets the read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	s.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	return nil
}

// HandlePacket processes an incoming packet.
func (s *Stream) HandlePacket(pkt *Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.packetsReceived++

	// Handle RST
	if pkt.IsReset() {
		s.state = StateClosed
		close(s.closed)
		return ErrStreamReset
	}

	// Handle SYN
	if pkt.IsSYN() {
		if s.state == StateSynSent {
			// SYN-ACK received
			s.receiveStreamID = pkt.SendStreamID
			s.state = StateEstablished
			s.recvSeqNum = pkt.SequenceNum + 1

			// Signal connect complete
			select {
			case s.writeReady <- struct{}{}:
			default:
			}
		}
		return nil
	}

	// Handle Close
	if pkt.IsClose() {
		s.state = StateClosing
		// Send ACK for close
		return nil
	}

	// Process ACKs
	if pkt.AckThrough > 0 {
		s.processAcks(pkt.AckThrough, pkt.NACKs)
	}

	// Process payload
	if len(pkt.Payload) > 0 {
		if pkt.SequenceNum == s.recvSeqNum {
			// In-order packet
			s.appendToBuffer(pkt.Payload)
			s.recvSeqNum++
			s.bytesReceived += int64(len(pkt.Payload))

			// Check for buffered out-of-order packets
			for {
				if data, ok := s.outOfOrder[s.recvSeqNum]; ok {
					s.appendToBuffer(data)
					delete(s.outOfOrder, s.recvSeqNum)
					s.recvSeqNum++
				} else {
					break
				}
			}

			// Signal data available
			select {
			case s.readReady <- struct{}{}:
			default:
			}
		} else if pkt.SequenceNum > s.recvSeqNum {
			// Out-of-order packet - buffer it
			s.outOfOrder[pkt.SequenceNum] = pkt.Payload
		}
		// Ignore duplicates (seq < recvSeqNum)

		s.ackThrough = s.recvSeqNum - 1
	}

	return nil
}

// sendPacket sends a packet to the remote destination.
func (s *Stream) sendPacket(pkt *Packet) error {
	if s.remoteDest == nil {
		return ErrNoDestination
	}

	pktBytes := pkt.ToBytes()

	s.mu.Lock()
	s.packetsSent++

	// Track for retransmission if has payload
	if len(pkt.Payload) > 0 || pkt.IsSYN() {
		s.unacked[pkt.SequenceNum] = &unackedPacket{
			packet:  pkt,
			sentAt:  time.Now(),
			retries: 0,
		}
	}
	s.mu.Unlock()

	destHash := s.remoteDest.GetIdentHash()
	return s.sendFunc(destHash, pktBytes)
}

// processAcks processes ACKs and NACKs.
func (s *Stream) processAcks(ackThrough uint32, nacks []uint32) {
	// Build NACK set
	nackSet := make(map[uint32]bool)
	for _, n := range nacks {
		nackSet[n] = true
	}

	// Remove acknowledged packets
	for seq := range s.unacked {
		if seq <= ackThrough && !nackSet[seq] {
			// Update RTT estimate
			if unacked, ok := s.unacked[seq]; ok && unacked.retries == 0 {
				rtt := time.Since(unacked.sentAt)
				s.updateRTT(rtt)
			}
			delete(s.unacked, seq)

			// Update congestion window
			if s.congestionWnd < s.slowStartThresh {
				// Slow start
				s.congestionWnd++
			} else {
				// Congestion avoidance
				s.congestionWnd += 1 / s.congestionWnd
			}
		}
	}

	// Signal write ready if window opens up
	if len(s.unacked) < s.congestionWnd {
		select {
		case s.writeReady <- struct{}{}:
		default:
		}
	}
}

// updateRTT updates the RTT estimate using Jacobson/Karels algorithm.
func (s *Stream) updateRTT(measured time.Duration) {
	// SRTT = (1-alpha)*SRTT + alpha*R
	// RTTVAR = (1-beta)*RTTVAR + beta*|SRTT-R|
	// RTO = SRTT + 4*RTTVAR

	diff := s.rtt - measured
	if diff < 0 {
		diff = -diff
	}

	s.rttVar = (3*s.rttVar + diff) / 4
	s.rtt = (7*s.rtt + measured) / 8

	// Clamp
	if s.rtt < MinRTT {
		s.rtt = MinRTT
	}
	if s.rtt > MaxRTT {
		s.rtt = MaxRTT
	}
}

// appendToBuffer appends data to the read buffer.
func (s *Stream) appendToBuffer(data []byte) {
	// Compact buffer if needed
	if s.readEnd+len(data) > len(s.readBuffer) {
		if s.readPos > 0 {
			copy(s.readBuffer, s.readBuffer[s.readPos:s.readEnd])
			s.readEnd -= s.readPos
			s.readPos = 0
		}
	}

	// Append data
	if s.readEnd+len(data) <= len(s.readBuffer) {
		copy(s.readBuffer[s.readEnd:], data)
		s.readEnd += len(data)
	}
	// Drop data if buffer full (shouldn't happen with proper flow control)
}

// buildSYNOptions builds the options for a SYN packet.
func (s *Stream) buildSYNOptions() []byte {
	// Options: MaxPacketSize (2) + From (Destination) + Signature (64)
	var options []byte

	// Max packet size
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, DefaultMTU)
	options = append(options, sizeBytes...)

	// From (local destination)
	if s.localDest != nil {
		options = append(options, s.localDest.ToBuffer()...)
	}

	// Signature placeholder (would be signed in production)
	sig := make([]byte, 64)
	options = append(options, sig...)

	return options
}

// generateStreamID generates a random stream ID.
func generateStreamID() StreamID {
	var id [4]byte
	rand.Read(id[:])
	return StreamID(binary.BigEndian.Uint32(id[:]))
}

// Stats returns stream statistics.
func (s *Stream) Stats() StreamStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return StreamStats{
		State:           s.state,
		SendStreamID:    s.sendStreamID,
		ReceiveStreamID: s.receiveStreamID,
		BytesSent:       s.bytesSent,
		BytesReceived:   s.bytesReceived,
		PacketsSent:     s.packetsSent,
		PacketsReceived: s.packetsReceived,
		Retransmits:     s.retransmits,
		RTT:             s.rtt,
		WindowSize:      s.congestionWnd,
	}
}

// streamAddr implements net.Addr for stream addresses.
type streamAddr struct {
	dest *data.Destination
}

func (a *streamAddr) Network() string { return "i2p" }

func (a *streamAddr) String() string {
	if a.dest == nil {
		return "<nil>"
	}
	return a.dest.Base32()
}

// timeoutError implements net.Error for timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
