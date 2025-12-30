package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS protocol constants
const (
	SOCKS4        = 0x04
	SOCKS5        = 0x05

	// SOCKS5 auth methods
	AuthNone     = 0x00
	AuthGSSAPI   = 0x01
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	// SOCKS5 commands
	CmdConnect = 0x01
	CmdBind    = 0x02
	CmdUDP     = 0x03

	// SOCKS5 address types
	AddrIPv4   = 0x01
	AddrDomain = 0x03
	AddrIPv6   = 0x04

	// SOCKS5 reply codes
	RepSuccess         = 0x00
	RepGeneralFailure  = 0x01
	RepNotAllowed      = 0x02
	RepNetUnreachable  = 0x03
	RepHostUnreachable = 0x04
	RepConnRefused     = 0x05
	RepTTLExpired      = 0x06
	RepCmdNotSupported = 0x07
	RepAddrNotSupported = 0x08
)

// SOCKSProxy is a SOCKS4/5 proxy for I2P.
type SOCKSProxy struct {
	mu sync.RWMutex

	listener    net.Listener
	address     string
	dialer      I2PDialer
	addressBook AddressResolver
	running     bool
	done        chan struct{}

	// Stats
	requestCount int64
	errorCount   int64

	// Configuration
	timeout      time.Duration
	allowClearnet bool
	requireAuth  bool
	username     string
	password     string
}

// SOCKSProxyConfig holds SOCKS proxy configuration.
type SOCKSProxyConfig struct {
	Address       string
	Timeout       time.Duration
	AllowClearnet bool
	RequireAuth   bool
	Username      string
	Password      string
}

// DefaultSOCKSProxyConfig returns the default configuration.
func DefaultSOCKSProxyConfig() *SOCKSProxyConfig {
	return &SOCKSProxyConfig{
		Address:       "127.0.0.1:4447",
		Timeout:       60 * time.Second,
		AllowClearnet: false,
		RequireAuth:   false,
	}
}

// NewSOCKSProxy creates a new SOCKS proxy.
func NewSOCKSProxy(config *SOCKSProxyConfig, dialer I2PDialer, addressBook AddressResolver) *SOCKSProxy {
	if config == nil {
		config = DefaultSOCKSProxyConfig()
	}
	return &SOCKSProxy{
		address:       config.Address,
		dialer:        dialer,
		addressBook:   addressBook,
		timeout:       config.Timeout,
		allowClearnet: config.AllowClearnet,
		requireAuth:   config.RequireAuth,
		username:      config.Username,
		password:      config.Password,
		done:          make(chan struct{}),
	}
}

// Start starts the SOCKS proxy.
func (p *SOCKSProxy) Start() error {
	listener, err := net.Listen("tcp", p.address)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.listener = listener
	p.running = true
	p.mu.Unlock()

	go p.acceptLoop()

	return nil
}

// Stop stops the SOCKS proxy.
func (p *SOCKSProxy) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	close(p.done)
	err := p.listener.Close()
	p.mu.Unlock()
	return err
}

// acceptLoop accepts new connections.
func (p *SOCKSProxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				continue
			}
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a new client connection.
func (p *SOCKSProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))

	// Read version byte
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return
	}

	p.mu.Lock()
	p.requestCount++
	p.mu.Unlock()

	switch version[0] {
	case SOCKS4:
		p.handleSOCKS4(conn)
	case SOCKS5:
		p.handleSOCKS5(conn)
	default:
		return
	}
}

// handleSOCKS4 handles SOCKS4/4a requests.
func (p *SOCKSProxy) handleSOCKS4(conn net.Conn) {
	// Read SOCKS4 request: CMD(1) + DSTPORT(2) + DSTIP(4) + USERID + NULL
	header := make([]byte, 7)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	cmd := header[0]
	port := binary.BigEndian.Uint16(header[1:3])
	ip := net.IP(header[3:7])

	// Read userid (null-terminated)
	userid := make([]byte, 0)
	for {
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		if b[0] == 0 {
			break
		}
		userid = append(userid, b[0])
	}

	// Check for SOCKS4a (domain name)
	var host string
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		// SOCKS4a: read domain name
		domain := make([]byte, 0)
		for {
			b := make([]byte, 1)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			if b[0] == 0 {
				break
			}
			domain = append(domain, b[0])
		}
		host = string(domain)
	} else {
		host = ip.String()
	}

	// Only support CONNECT
	if cmd != CmdConnect {
		p.sendSOCKS4Reply(conn, 0x5B) // Request rejected
		return
	}

	// Check if it's an I2P address
	if !isI2PAddress(host) {
		if !p.allowClearnet {
			p.sendSOCKS4Reply(conn, 0x5B)
			return
		}
	}

	// Connect to I2P destination
	targetHost := host
	if port != 0 {
		targetHost = host // Port is implicit for I2P
	}

	i2pConn, err := p.dialer.DialI2P(targetHost)
	if err != nil {
		p.mu.Lock()
		p.errorCount++
		p.mu.Unlock()
		p.sendSOCKS4Reply(conn, 0x5B)
		return
	}
	defer i2pConn.Close()

	// Send success reply
	p.sendSOCKS4Reply(conn, 0x5A)

	// Bridge connections
	p.bridge(conn, i2pConn)
}

// sendSOCKS4Reply sends a SOCKS4 reply.
func (p *SOCKSProxy) sendSOCKS4Reply(conn net.Conn, status byte) {
	reply := []byte{0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(reply)
}

// handleSOCKS5 handles SOCKS5 requests.
func (p *SOCKSProxy) handleSOCKS5(conn net.Conn) {
	// Read auth methods
	nmethods := make([]byte, 1)
	if _, err := io.ReadFull(conn, nmethods); err != nil {
		return
	}

	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Select auth method
	authMethod := byte(AuthNoAccept)
	if p.requireAuth {
		for _, m := range methods {
			if m == AuthPassword {
				authMethod = AuthPassword
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == AuthNone {
				authMethod = AuthNone
				break
			}
		}
	}

	// Send auth method selection
	conn.Write([]byte{SOCKS5, authMethod})

	if authMethod == AuthNoAccept {
		return
	}

	// Handle password auth if required
	if authMethod == AuthPassword {
		if !p.handlePasswordAuth(conn) {
			return
		}
	}

	// Read request
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	if header[0] != SOCKS5 {
		return
	}

	cmd := header[1]
	addrType := header[3]

	// Read address
	var host string
	switch addrType {
	case AddrIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case AddrDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case AddrIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		p.sendSOCKS5Reply(conn, RepAddrNotSupported, nil)
		return
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes)
	_ = port // Port is implicit for I2P

	// Only support CONNECT
	if cmd != CmdConnect {
		p.sendSOCKS5Reply(conn, RepCmdNotSupported, nil)
		return
	}

	// Check if it's an I2P address
	if !isI2PAddress(host) {
		if !p.allowClearnet {
			p.sendSOCKS5Reply(conn, RepNotAllowed, nil)
			return
		}
	}

	// Connect to I2P destination
	i2pConn, err := p.dialer.DialI2P(host)
	if err != nil {
		p.mu.Lock()
		p.errorCount++
		p.mu.Unlock()
		p.sendSOCKS5Reply(conn, RepHostUnreachable, nil)
		return
	}
	defer i2pConn.Close()

	// Send success reply
	p.sendSOCKS5Reply(conn, RepSuccess, net.IPv4zero)

	// Bridge connections
	p.bridge(conn, i2pConn)
}

// handlePasswordAuth handles SOCKS5 username/password authentication.
func (p *SOCKSProxy) handlePasswordAuth(conn net.Conn) bool {
	// Read auth version
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return false
	}
	if version[0] != 0x01 {
		return false
	}

	// Read username
	ulen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulen); err != nil {
		return false
	}
	username := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return false
	}

	// Read password
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return false
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return false
	}

	// Verify credentials
	if string(username) == p.username && string(password) == p.password {
		conn.Write([]byte{0x01, 0x00}) // Success
		return true
	}

	conn.Write([]byte{0x01, 0x01}) // Failure
	return false
}

// sendSOCKS5Reply sends a SOCKS5 reply.
func (p *SOCKSProxy) sendSOCKS5Reply(conn net.Conn, status byte, bindAddr net.IP) {
	reply := []byte{SOCKS5, status, 0x00, AddrIPv4}
	if bindAddr == nil {
		bindAddr = net.IPv4zero
	}
	reply = append(reply, bindAddr.To4()...)
	reply = append(reply, 0x00, 0x00) // Port
	conn.Write(reply)
}

// bridge bridges two connections.
func (p *SOCKSProxy) bridge(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
	}

	go copy(conn2, conn1)
	go copy(conn1, conn2)

	wg.Wait()
}

// Stats returns proxy statistics.
func (p *SOCKSProxy) Stats() (requests, errors int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.requestCount, p.errorCount
}

// Address returns the proxy address.
func (p *SOCKSProxy) Address() string {
	return p.address
}

// Ensure errors are exported
var (
	_ = errors.New
)
