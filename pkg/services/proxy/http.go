// Package proxy implements HTTP and SOCKS proxies for I2P.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Errors
var (
	ErrNotI2PAddress   = errors.New("proxy: not an I2P address")
	ErrHostNotFound    = errors.New("proxy: host not found")
	ErrConnectFailed   = errors.New("proxy: connection failed")
	ErrNoAddressBook   = errors.New("proxy: no address book configured")
)

// I2PDialer is the interface for dialing I2P destinations.
type I2PDialer interface {
	// DialI2P dials an I2P destination by hostname or Base32 address.
	DialI2P(host string) (net.Conn, error)
}

// AddressResolver resolves .i2p hostnames to destinations.
type AddressResolver interface {
	// LookupB64 looks up a hostname and returns the Base64 destination.
	LookupB64(hostname string) (string, error)
}

// HTTPProxy is an HTTP proxy for accessing I2P sites.
type HTTPProxy struct {
	mu sync.RWMutex

	listener    net.Listener
	address     string
	dialer      I2PDialer
	addressBook AddressResolver
	running     bool
	done        chan struct{}

	// Stats
	requestCount  int64
	errorCount    int64
	bytesIn       int64
	bytesOut      int64

	// Configuration
	userAgent     string
	timeout       time.Duration
	allowClearnet bool
}

// HTTPProxyConfig holds proxy configuration.
type HTTPProxyConfig struct {
	Address       string
	UserAgent     string
	Timeout       time.Duration
	AllowClearnet bool
}

// DefaultHTTPProxyConfig returns the default configuration.
func DefaultHTTPProxyConfig() *HTTPProxyConfig {
	return &HTTPProxyConfig{
		Address:       "127.0.0.1:4444",
		UserAgent:     "I2P-HTTP-Proxy/1.0",
		Timeout:       60 * time.Second,
		AllowClearnet: false,
	}
}

// NewHTTPProxy creates a new HTTP proxy.
func NewHTTPProxy(config *HTTPProxyConfig, dialer I2PDialer, addressBook AddressResolver) *HTTPProxy {
	if config == nil {
		config = DefaultHTTPProxyConfig()
	}
	return &HTTPProxy{
		address:       config.Address,
		dialer:        dialer,
		addressBook:   addressBook,
		userAgent:     config.UserAgent,
		timeout:       config.Timeout,
		allowClearnet: config.AllowClearnet,
		done:          make(chan struct{}),
	}
}

// Start starts the HTTP proxy.
func (p *HTTPProxy) Start() error {
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

// Stop stops the HTTP proxy.
func (p *HTTPProxy) Stop() error {
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
func (p *HTTPProxy) acceptLoop() {
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
func (p *HTTPProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.timeout))

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.sendError(conn, http.StatusBadRequest, "Invalid request")
		return
	}

	p.mu.Lock()
	p.requestCount++
	p.mu.Unlock()

	// Handle CONNECT method (for HTTPS tunneling)
	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
		return
	}

	// Handle regular HTTP requests
	p.handleHTTP(conn, req)
}

// handleHTTP handles regular HTTP requests.
func (p *HTTPProxy) handleHTTP(conn net.Conn, req *http.Request) {
	// Determine target host
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Check if it's an I2P address
	if !isI2PAddress(host) {
		if !p.allowClearnet {
			p.sendError(conn, http.StatusForbidden, "Only I2P addresses are allowed")
			return
		}
		// Handle clearnet proxy (not implemented for security)
		p.sendError(conn, http.StatusForbidden, "Clearnet proxying disabled")
		return
	}

	// Resolve hostname if needed
	targetHost := host
	if !isBase32Address(host) && !isBase64Address(host) {
		hostname := strings.TrimSuffix(strings.ToLower(host), ":80")
		if p.addressBook == nil {
			p.sendError(conn, http.StatusBadGateway, "Address book not configured")
			return
		}
		_, err := p.addressBook.LookupB64(hostname)
		if err != nil {
			// Try jump service or return error
			p.sendJumpPage(conn, hostname)
			return
		}
		targetHost = hostname
	}

	// Connect to I2P destination
	i2pConn, err := p.dialer.DialI2P(targetHost)
	if err != nil {
		p.mu.Lock()
		p.errorCount++
		p.mu.Unlock()
		p.sendError(conn, http.StatusBadGateway, "Failed to connect to destination")
		return
	}
	defer i2pConn.Close()

	// Forward the request
	p.forwardRequest(conn, i2pConn, req)
}

// handleConnect handles CONNECT requests (HTTPS tunneling).
func (p *HTTPProxy) handleConnect(conn net.Conn, req *http.Request) {
	host := req.Host

	// Check if it's an I2P address
	if !isI2PAddress(host) {
		if !p.allowClearnet {
			p.sendError(conn, http.StatusForbidden, "Only I2P addresses are allowed")
			return
		}
		p.sendError(conn, http.StatusForbidden, "Clearnet proxying disabled")
		return
	}

	// Parse host and port
	targetHost := host
	colonIdx := strings.LastIndex(host, ":")
	if colonIdx != -1 {
		targetHost = host[:colonIdx]
	}

	// Resolve if needed
	if !isBase32Address(targetHost) && !isBase64Address(targetHost) {
		if p.addressBook != nil {
			if _, err := p.addressBook.LookupB64(targetHost); err != nil {
				p.sendError(conn, http.StatusBadGateway, "Host not found")
				return
			}
		}
	}

	// Connect to I2P destination
	i2pConn, err := p.dialer.DialI2P(targetHost)
	if err != nil {
		p.mu.Lock()
		p.errorCount++
		p.mu.Unlock()
		p.sendError(conn, http.StatusBadGateway, "Failed to connect to destination")
		return
	}
	defer i2pConn.Close()

	// Send 200 Connection Established
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bridge the connections
	p.bridge(conn, i2pConn)
}

// forwardRequest forwards an HTTP request to the I2P destination.
func (p *HTTPProxy) forwardRequest(client, server net.Conn, req *http.Request) {
	// Modify request for forwarding
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if p.userAgent != "" {
		req.Header.Set("User-Agent", p.userAgent)
	}

	// Write request to server
	if err := req.Write(server); err != nil {
		p.sendError(client, http.StatusBadGateway, "Failed to send request")
		return
	}

	// Read and forward response
	serverReader := bufio.NewReader(server)
	resp, err := http.ReadResponse(serverReader, req)
	if err != nil {
		p.sendError(client, http.StatusBadGateway, "Failed to read response")
		return
	}
	defer resp.Body.Close()

	// Write response to client
	resp.Write(client)
}

// bridge bridges two connections.
func (p *HTTPProxy) bridge(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		p.mu.Lock()
		p.bytesIn += n
		p.mu.Unlock()
	}

	go copy(conn2, conn1)
	go copy(conn1, conn2)

	wg.Wait()
}

// sendError sends an HTTP error response.
func (p *HTTPProxy) sendError(conn net.Conn, status int, message string) {
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>I2P Proxy Error</title></head>
<body>
<h1>Proxy Error %d</h1>
<p>%s</p>
<hr>
<p><i>I2P HTTP Proxy</i> - <a href="https://github.com/blubskye/i2p_go">Source Code</a></p>
</body>
</html>`, status, message)

	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", status, http.StatusText(status), len(body), body)

	conn.Write([]byte(resp))
}

// sendJumpPage sends a jump service page.
func (p *HTTPProxy) sendJumpPage(conn net.Conn, hostname string) {
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>I2P Address Not Found</title>
<style>
body { font-family: sans-serif; margin: 40px; }
h1 { color: #333; }
.jump-links { margin: 20px 0; }
.jump-links a { display: block; margin: 10px 0; }
input[type="text"] { width: 400px; padding: 5px; }
</style>
</head>
<body>
<h1>Address Not Found</h1>
<p>The I2P address <b>%s</b> was not found in the local address book.</p>

<h2>Jump Services</h2>
<p>Try one of these jump services to add the address:</p>
<div class="jump-links">
<a href="http://stats.i2p/cgi-bin/jump.cgi?a=%s">stats.i2p jump service</a>
<a href="http://i2p-projekt.i2p/cgi-bin/jump.cgi?a=%s">i2p-projekt.i2p jump service</a>
<a href="http://no.i2p/jump/%s">no.i2p jump service</a>
</div>

<h2>Manual Entry</h2>
<p>If you have the Base64 destination, you can add it manually:</p>
<form method="GET" action="/i2p-proxy/addressbook/add">
<input type="hidden" name="host" value="%s">
<input type="text" name="dest" placeholder="Base64 destination...">
<button type="submit">Add to Address Book</button>
</form>

<hr>
<p><i>I2P HTTP Proxy</i> - <a href="https://github.com/blubskye/i2p_go">Source Code</a></p>
</body>
</html>`, hostname, url.QueryEscape(hostname), url.QueryEscape(hostname), url.QueryEscape(hostname), hostname)

	resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", len(body), body)

	conn.Write([]byte(resp))
}

// Stats returns proxy statistics.
func (p *HTTPProxy) Stats() (requests, errors, bytesIn, bytesOut int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.requestCount, p.errorCount, p.bytesIn, p.bytesOut
}

// Address returns the proxy address.
func (p *HTTPProxy) Address() string {
	return p.address
}

// isI2PAddress checks if a host is an I2P address.
func isI2PAddress(host string) bool {
	host = strings.ToLower(host)
	// Remove port if present
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	return strings.HasSuffix(host, ".i2p") ||
		strings.HasSuffix(host, ".b32.i2p") ||
		isBase32Address(host) ||
		isBase64Address(host)
}

// isBase32Address checks if it's a Base32 I2P address.
func isBase32Address(host string) bool {
	host = strings.ToLower(host)
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	return strings.HasSuffix(host, ".b32.i2p") && len(host) == 60 // 52 chars + ".b32.i2p"
}

// isBase64Address checks if it's a Base64 destination (very long).
func isBase64Address(host string) bool {
	return len(host) > 500 // Base64 destinations are 516+ chars
}
