package sam

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/streaming"
)

// Server is a SAMv3 protocol server.
type Server struct {
	mu sync.RWMutex

	listener    net.Listener
	address     string
	sessions    map[string]*Session
	destManager DestinationManager
	running     bool
	done        chan struct{}
}

// DestinationManager provides destination and streaming services.
type DestinationManager interface {
	// CreateDestination creates a new destination.
	CreateDestination(sigType int) (*data.PrivateKeys, error)
	// LookupDestination looks up a destination by hash or name.
	LookupDestination(name string) (*data.Destination, error)
	// GetStreamingManager gets the streaming manager for a destination.
	GetStreamingManager(keys *data.PrivateKeys) (*streaming.Manager, error)
	// PublishLeaseSet publishes a leaseset for the destination.
	PublishLeaseSet(keys *data.PrivateKeys) error
}

// NewServer creates a new SAM server.
func NewServer(address string, destManager DestinationManager) *Server {
	return &Server{
		address:     address,
		sessions:    make(map[string]*Session),
		destManager: destManager,
		done:        make(chan struct{}),
	}
}

// Start starts the SAM server.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	go s.acceptLoop()

	return nil
}

// Stop stops the SAM server.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.done)

	// Close all sessions
	for _, session := range s.sessions {
		session.Close()
	}
	s.sessions = make(map[string]*Session)

	err := s.listener.Close()
	s.mu.Unlock()

	return err
}

// acceptLoop accepts incoming connections.
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a SAM client connection.
func (s *Server) handleConnection(conn net.Conn) {
	client := &Client{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		server:  s,
		session: nil,
	}

	defer client.Close()

	// Read and process commands
	for {
		line, err := client.reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := client.handleCommand(line); err != nil {
			return
		}
	}
}

// getSession gets a session by ID.
func (s *Server) getSession(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// addSession adds a session.
func (s *Server) addSession(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.ID]; exists {
		return ErrDuplicatedID
	}

	s.sessions[session.ID] = session
	return nil
}

// removeSession removes a session.
func (s *Server) removeSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// Client represents a SAM client connection.
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	server  *Server
	session *Session
	version string
}

// Close closes the client connection.
func (c *Client) Close() {
	c.conn.Close()
}

// handleCommand handles a SAM command.
func (c *Client) handleCommand(line string) error {
	parts := strings.Fields(line)
	if len(parts) < 1 {
		return nil
	}

	cmd := parts[0]
	args := parseArgs(parts[1:])

	switch cmd {
	case CmdHello:
		return c.handleHello(args)
	case CmdSession:
		return c.handleSession(args)
	case CmdStream:
		return c.handleStream(args)
	case CmdDatagram:
		return c.handleDatagram(args)
	case CmdDest:
		return c.handleDest(args)
	case CmdNaming:
		return c.handleNaming(args)
	case CmdPing:
		return c.handlePing(args)
	default:
		c.sendReply(cmd, "REPLY", ResultI2PError, "Unknown command")
		return nil
	}
}

// handleHello handles HELLO VERSION.
func (c *Client) handleHello(args map[string]string) error {
	minVer := args["MIN"]
	maxVer := args["MAX"]

	// Check version compatibility
	version := SAMVersion31
	if maxVer >= SAMVersion33 && minVer <= SAMVersion33 {
		version = SAMVersion33
	} else if maxVer >= SAMVersion32 && minVer <= SAMVersion32 {
		version = SAMVersion32
	} else if maxVer >= SAMVersion31 && minVer <= SAMVersion31 {
		version = SAMVersion31
	}

	c.version = version

	c.send(fmt.Sprintf("HELLO REPLY RESULT=OK VERSION=%s\n", version))
	return nil
}

// handleSession handles SESSION CREATE.
func (c *Client) handleSession(args map[string]string) error {
	action := args[""]
	if action == "" {
		// Check first positional arg
		for k := range args {
			if args[k] == "" {
				action = k
				break
			}
		}
	}

	switch action {
	case "CREATE":
		return c.handleSessionCreate(args)
	case "ADD":
		return c.handleSessionAdd(args)
	case "REMOVE":
		return c.handleSessionRemove(args)
	default:
		c.sendReply(CmdSession, "STATUS", ResultI2PError, "Unknown session action")
		return nil
	}
}

// handleSessionCreate handles SESSION CREATE.
func (c *Client) handleSessionCreate(args map[string]string) error {
	style := args["STYLE"]
	id := args["ID"]
	dest := args["DESTINATION"]

	if id == "" {
		c.sendReply(CmdSession, "STATUS", ResultInvalidID, "No ID specified")
		return nil
	}

	// Check for existing session
	if c.server.getSession(id) != nil {
		c.sendReply(CmdSession, "STATUS", ResultDuplicatedID, "Session ID exists")
		return nil
	}

	// Create or use destination
	var keys *data.PrivateKeys
	var err error

	if dest == "TRANSIENT" || dest == "" {
		// Create new transient destination
		sigType := SigTypeEdDSA_SHA512_Ed25519
		if st, ok := args[OptSignatureType]; ok {
			fmt.Sscanf(st, "%d", &sigType)
		}

		keys, err = c.server.destManager.CreateDestination(sigType)
		if err != nil {
			c.sendReply(CmdSession, "STATUS", ResultI2PError, err.Error())
			return nil
		}
	} else {
		// Use provided destination (Base64)
		decoded, err := data.Base64Decode(dest)
		if err != nil {
			c.sendReply(CmdSession, "STATUS", ResultInvalidKey, "Invalid destination")
			return nil
		}

		keys, err = data.NewPrivateKeysFromBytes(decoded)
		if err != nil {
			c.sendReply(CmdSession, "STATUS", ResultInvalidKey, "Invalid private keys")
			return nil
		}
	}

	// Create session
	session := &Session{
		ID:     id,
		Style:  style,
		Keys:   keys,
		client: c,
		server: c.server,
	}

	// Get streaming manager
	if style == StyleStream {
		session.streamManager, err = c.server.destManager.GetStreamingManager(keys)
		if err != nil {
			c.sendReply(CmdSession, "STATUS", ResultI2PError, err.Error())
			return nil
		}
	}

	// Add session
	if err := c.server.addSession(session); err != nil {
		c.sendReply(CmdSession, "STATUS", ResultDuplicatedID, "Session ID exists")
		return nil
	}

	c.session = session

	// Publish leaseset
	go c.server.destManager.PublishLeaseSet(keys)

	// Send reply with destination
	destB64 := data.Base64Encode(keys.Identity.ToBuffer())
	c.send(fmt.Sprintf("SESSION STATUS RESULT=OK DESTINATION=%s\n", destB64))

	return nil
}

// handleSessionAdd handles SESSION ADD (subsession).
func (c *Client) handleSessionAdd(args map[string]string) error {
	c.sendReply(CmdSession, "STATUS", ResultOK, "")
	return nil
}

// handleSessionRemove handles SESSION REMOVE.
func (c *Client) handleSessionRemove(args map[string]string) error {
	id := args["ID"]
	if session := c.server.getSession(id); session != nil {
		session.Close()
		c.server.removeSession(id)
	}
	c.sendReply(CmdSession, "STATUS", ResultOK, "")
	return nil
}

// handleStream handles STREAM CONNECT/ACCEPT.
func (c *Client) handleStream(args map[string]string) error {
	action := ""
	for k := range args {
		if args[k] == "" && k != "" {
			action = k
			break
		}
	}

	switch action {
	case "CONNECT":
		return c.handleStreamConnect(args)
	case "ACCEPT":
		return c.handleStreamAccept(args)
	case "FORWARD":
		return c.handleStreamForward(args)
	default:
		c.sendReply(CmdStream, "STATUS", ResultI2PError, "Unknown stream action")
		return nil
	}
}

// handleStreamConnect handles STREAM CONNECT.
func (c *Client) handleStreamConnect(args map[string]string) error {
	id := args["ID"]
	dest := args["DESTINATION"]
	silent := args["SILENT"] == "true"

	session := c.server.getSession(id)
	if session == nil {
		c.sendReply(CmdStream, "STATUS", ResultInvalidID, "No such session")
		return nil
	}

	// Lookup destination
	destObj, err := c.server.destManager.LookupDestination(dest)
	if err != nil {
		c.sendReply(CmdStream, "STATUS", ResultCantReachPeer, "Cannot reach peer")
		return nil
	}

	// Connect stream
	if session.streamManager == nil {
		c.sendReply(CmdStream, "STATUS", ResultI2PError, "Not a stream session")
		return nil
	}

	stream, err := session.streamManager.Dial(destObj)
	if err != nil {
		c.sendReply(CmdStream, "STATUS", ResultCantReachPeer, err.Error())
		return nil
	}

	if !silent {
		c.send(fmt.Sprintf("STREAM STATUS RESULT=OK\n"))
	}

	// Bridge the connection
	go func() {
		defer stream.Close()
		defer c.conn.Close()

		// Copy data bidirectionally
		done := make(chan struct{})

		go func() {
			buf := make([]byte, 32768)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					close(done)
					return
				}
				if _, err := c.conn.Write(buf[:n]); err != nil {
					close(done)
					return
				}
			}
		}()

		buf := make([]byte, 32768)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := c.conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	return nil
}

// handleStreamAccept handles STREAM ACCEPT.
func (c *Client) handleStreamAccept(args map[string]string) error {
	id := args["ID"]
	silent := args["SILENT"] == "true"

	session := c.server.getSession(id)
	if session == nil {
		c.sendReply(CmdStream, "STATUS", ResultInvalidID, "No such session")
		return nil
	}

	if session.streamManager == nil {
		c.sendReply(CmdStream, "STATUS", ResultI2PError, "Not a stream session")
		return nil
	}

	// Accept incoming stream
	stream, err := session.streamManager.Accept()
	if err != nil {
		c.sendReply(CmdStream, "STATUS", ResultI2PError, err.Error())
		return nil
	}

	if !silent {
		// Get remote destination
		remoteAddr := stream.RemoteAddr()
		c.send(fmt.Sprintf("STREAM STATUS RESULT=OK DESTINATION=%s\n", remoteAddr.String()))
	}

	// Bridge the connection (similar to CONNECT)
	go func() {
		defer stream.Close()
		defer c.conn.Close()

		done := make(chan struct{})

		go func() {
			buf := make([]byte, 32768)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					close(done)
					return
				}
				if _, err := c.conn.Write(buf[:n]); err != nil {
					close(done)
					return
				}
			}
		}()

		buf := make([]byte, 32768)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := c.conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	return nil
}

// handleStreamForward handles STREAM FORWARD.
func (c *Client) handleStreamForward(args map[string]string) error {
	id := args["ID"]
	port := args["PORT"]
	host := args["HOST"]
	if host == "" {
		host = "127.0.0.1"
	}

	session := c.server.getSession(id)
	if session == nil {
		c.sendReply(CmdStream, "STATUS", ResultInvalidID, "No such session")
		return nil
	}

	// Start forwarding accepted connections to local port
	go func() {
		for {
			if session.streamManager == nil {
				return
			}

			stream, err := session.streamManager.Accept()
			if err != nil {
				return
			}

			// Connect to local port
			local, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
			if err != nil {
				stream.Close()
				continue
			}

			// Bridge connections
			go func() {
				defer stream.Close()
				defer local.Close()

				done := make(chan struct{})
				go func() {
					buf := make([]byte, 32768)
					for {
						n, err := stream.Read(buf)
						if err != nil {
							close(done)
							return
						}
						local.Write(buf[:n])
					}
				}()

				buf := make([]byte, 32768)
				for {
					select {
					case <-done:
						return
					default:
					}
					n, err := local.Read(buf)
					if err != nil {
						return
					}
					stream.Write(buf[:n])
				}
			}()
		}
	}()

	c.sendReply(CmdStream, "STATUS", ResultOK, "")
	return nil
}

// handleDatagram handles DATAGRAM SEND.
func (c *Client) handleDatagram(args map[string]string) error {
	c.sendReply(CmdDatagram, "STATUS", ResultI2PError, "Datagrams not implemented")
	return nil
}

// handleDest handles DEST GENERATE.
func (c *Client) handleDest(args map[string]string) error {
	action := ""
	for k := range args {
		if args[k] == "" && k != "" {
			action = k
			break
		}
	}

	if action != "GENERATE" {
		c.sendReply(CmdDest, "REPLY", ResultI2PError, "Unknown dest action")
		return nil
	}

	sigType := SigTypeEdDSA_SHA512_Ed25519
	if st, ok := args[OptSignatureType]; ok {
		fmt.Sscanf(st, "%d", &sigType)
	}

	keys, err := c.server.destManager.CreateDestination(sigType)
	if err != nil {
		c.sendReply(CmdDest, "REPLY", ResultI2PError, err.Error())
		return nil
	}

	pubDest := data.Base64Encode(keys.Identity.ToBuffer())
	privKey := data.Base64Encode(keys.ToBytes())

	c.send(fmt.Sprintf("DEST REPLY PUB=%s PRIV=%s\n", pubDest, privKey))
	return nil
}

// handleNaming handles NAMING LOOKUP.
func (c *Client) handleNaming(args map[string]string) error {
	action := ""
	for k := range args {
		if args[k] == "" && k != "" {
			action = k
			break
		}
	}

	if action != "LOOKUP" {
		c.sendReply(CmdNaming, "REPLY", ResultI2PError, "Unknown naming action")
		return nil
	}

	name := args["NAME"]
	if name == "" {
		c.sendReply(CmdNaming, "REPLY", ResultKeyNotFound, "No name specified")
		return nil
	}

	dest, err := c.server.destManager.LookupDestination(name)
	if err != nil {
		c.sendReply(CmdNaming, "REPLY", ResultKeyNotFound, err.Error())
		return nil
	}

	destB64 := data.Base64Encode(dest.ToBuffer())
	c.send(fmt.Sprintf("NAMING REPLY RESULT=OK NAME=%s VALUE=%s\n", name, destB64))
	return nil
}

// handlePing handles PING.
func (c *Client) handlePing(args map[string]string) error {
	c.send("PONG\n")
	return nil
}

// send sends a raw message.
func (c *Client) send(msg string) {
	c.conn.Write([]byte(msg))
}

// sendReply sends a formatted reply.
func (c *Client) sendReply(topic, typ, result, message string) {
	reply := fmt.Sprintf("%s %s RESULT=%s", topic, typ, result)
	if message != "" {
		reply += fmt.Sprintf(" MESSAGE=\"%s\"", message)
	}
	reply += "\n"
	c.send(reply)
}

// parseArgs parses SAM command arguments.
func parseArgs(parts []string) map[string]string {
	args := make(map[string]string)
	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			key := kv[0]
			value := kv[1]
			// Remove quotes if present
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			args[key] = value
		} else {
			// Positional argument (action)
			args[part] = ""
		}
	}
	return args
}
