package streaming

import (
	"net"
	"sync"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Manager handles streaming connections for a destination.
type Manager struct {
	mu sync.RWMutex

	// Local destination
	localDest *data.Destination
	keys      *data.PrivateKeys

	// Active streams by their stream ID
	streams map[StreamID]*Stream

	// Incoming connection queue
	acceptQueue chan *Stream

	// Message sender
	sendFunc func(dest data.Hash, payload []byte) error

	// State
	closed bool
	done   chan struct{}
}

// NewManager creates a new streaming manager.
func NewManager(dest *data.Destination, keys *data.PrivateKeys, sendFunc func(data.Hash, []byte) error) *Manager {
	return &Manager{
		localDest:   dest,
		keys:        keys,
		streams:     make(map[StreamID]*Stream),
		acceptQueue: make(chan *Stream, 16),
		sendFunc:    sendFunc,
		done:        make(chan struct{}),
	}
}

// Accept accepts an incoming stream connection.
func (m *Manager) Accept() (net.Conn, error) {
	select {
	case stream := <-m.acceptQueue:
		return stream, nil
	case <-m.done:
		return nil, ErrStreamClosed
	}
}

// Dial creates a new outgoing stream to a destination.
func (m *Manager) Dial(dest *data.Destination) (net.Conn, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrStreamClosed
	}

	stream := NewStream(m.localDest, m.sendFunc)
	m.streams[stream.sendStreamID] = stream
	m.mu.Unlock()

	// Connect
	if err := stream.Connect(dest); err != nil {
		m.mu.Lock()
		delete(m.streams, stream.sendStreamID)
		m.mu.Unlock()
		return nil, err
	}

	return stream, nil
}

// HandlePacket processes an incoming streaming packet.
func (m *Manager) HandlePacket(fromDest data.Hash, pktData []byte) error {
	pkt, err := ParsePacket(pktData)
	if err != nil {
		return err
	}

	m.mu.RLock()
	// Check if this is for an existing stream
	var stream *Stream
	if pkt.ReceiveStreamID != 0 {
		stream = m.streams[pkt.ReceiveStreamID]
	}
	m.mu.RUnlock()

	if stream != nil {
		return stream.HandlePacket(pkt)
	}

	// New incoming connection (SYN packet)
	if pkt.IsSYN() && pkt.ReceiveStreamID == 0 {
		return m.handleNewConnection(fromDest, pkt)
	}

	// Unknown stream - send RST
	if pkt.SendStreamID != 0 {
		rst := NewResetPacket(0, pkt.SendStreamID)
		return m.sendFunc(fromDest, rst.ToBytes())
	}

	return nil
}

// handleNewConnection handles an incoming SYN packet.
func (m *Manager) handleNewConnection(fromHash data.Hash, pkt *Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStreamClosed
	}

	// Create destination from the FROM field in the packet
	var remoteDest *data.Destination
	if pkt.HasFrom() && len(pkt.fromDest) > 0 {
		dest, err := data.NewDestination(pkt.fromDest)
		if err == nil {
			remoteDest = dest
		}
	}

	// Create inbound stream
	stream := NewInboundStream(m.localDest, remoteDest, pkt.SendStreamID, m.sendFunc)
	m.streams[stream.sendStreamID] = stream

	// Send SYN-ACK
	synAckOptions := stream.buildSYNOptions()
	synAck := NewSYNPacket(stream.sendStreamID, synAckOptions)
	synAck.ReceiveStreamID = pkt.SendStreamID
	synAck.AckThrough = pkt.SequenceNum

	if err := m.sendFunc(fromHash, synAck.ToBytes()); err != nil {
		delete(m.streams, stream.sendStreamID)
		return err
	}

	// Transition to established
	stream.state = StateEstablished
	stream.recvSeqNum = pkt.SequenceNum + 1

	// Queue for accept
	select {
	case m.acceptQueue <- stream:
	default:
		// Accept queue full, reject connection
		delete(m.streams, stream.sendStreamID)
		rst := NewResetPacket(stream.sendStreamID, pkt.SendStreamID)
		m.sendFunc(fromHash, rst.ToBytes())
	}

	return nil
}

// Close closes the manager and all streams.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true

	// Close all streams
	for _, stream := range m.streams {
		stream.Close()
	}
	m.streams = make(map[StreamID]*Stream)

	close(m.done)
	m.mu.Unlock()

	return nil
}

// Addr returns the local address.
func (m *Manager) Addr() net.Addr {
	return &streamAddr{dest: m.localDest}
}

// StreamCount returns the number of active streams.
func (m *Manager) StreamCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// GetStream returns a stream by its ID.
func (m *Manager) GetStream(id StreamID) *Stream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.streams[id]
}

// RemoveStream removes a stream.
func (m *Manager) RemoveStream(id StreamID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, id)
}

// Listener implements net.Listener interface for streaming.
type Listener struct {
	manager *Manager
}

// NewListener creates a new streaming listener.
func NewListener(manager *Manager) *Listener {
	return &Listener{manager: manager}
}

// Accept accepts an incoming connection.
func (l *Listener) Accept() (net.Conn, error) {
	return l.manager.Accept()
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.manager.Close()
}

// Addr returns the listener's address.
func (l *Listener) Addr() net.Addr {
	return l.manager.Addr()
}
