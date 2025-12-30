// Package jump implements a jump service for I2P address resolution.
// Jump services allow users to register and look up .i2p addresses.
package jump

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// AddressStore is the interface for address storage.
type AddressStore interface {
	// Add adds or updates an address.
	Add(hostname, destB64 string, local bool) error
	// Lookup looks up an address.
	LookupB64(hostname string) (string, error)
	// List lists addresses matching a filter.
	List(filter string) []AddressEntry
	// Count returns the total number of addresses.
	Count() int
}

// AddressEntry represents an address book entry.
type AddressEntry struct {
	Hostname    string
	Destination string
}

// Service is a jump service.
type Service struct {
	mu sync.RWMutex

	store     AddressStore
	listener  net.Listener
	server    *http.Server
	running   bool
	done      chan struct{}

	// Configuration
	serviceName  string
	allowAdd     bool
	requireAuth  bool
	authPassword string

	// Stats
	lookups     int64
	additions   int64
	startTime   time.Time
}

// Config holds jump service configuration.
type Config struct {
	ServiceName  string
	AllowAdd     bool
	RequireAuth  bool
	AuthPassword string
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		ServiceName: "I2P Jump Service",
		AllowAdd:    true,
		RequireAuth: false,
	}
}

// NewService creates a new jump service.
func NewService(store AddressStore, config *Config) *Service {
	if config == nil {
		config = DefaultConfig()
	}

	return &Service{
		store:        store,
		serviceName:  config.ServiceName,
		allowAdd:     config.AllowAdd,
		requireAuth:  config.RequireAuth,
		authPassword: config.AuthPassword,
		done:         make(chan struct{}),
		startTime:    time.Now(),
	}
}

// Start starts the jump service.
func (s *Service) Start(listener net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/jump", s.handleJump)
	mux.HandleFunc("/jump/", s.handleJump)
	mux.HandleFunc("/add", s.handleAdd)
	mux.HandleFunc("/lookup", s.handleLookup)
	mux.HandleFunc("/hosts.txt", s.handleHostsTxt)
	mux.HandleFunc("/api/lookup", s.handleAPILookup)
	mux.HandleFunc("/api/add", s.handleAPIAdd)
	mux.HandleFunc("/api/list", s.handleAPIList)

	s.mu.Lock()
	s.listener = listener
	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	s.running = true
	s.mu.Unlock()

	go s.server.Serve(listener)
	return nil
}

// StartLocal starts on a local address.
func (s *Service) StartLocal(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return s.Start(listener)
}

// Stop stops the jump service.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	return s.server.Close()
}

// handleIndex serves the main page.
func (s *Service) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	count := s.store.Count()

	tmpl := template.Must(template.New("index").Parse(indexTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"ServiceName": s.serviceName,
		"Count":       count,
		"AllowAdd":    s.allowAdd,
	})
}

// handleJump redirects to an I2P address.
func (s *Service) handleJump(w http.ResponseWriter, r *http.Request) {
	// Get hostname from query or path
	hostname := r.URL.Query().Get("a")
	if hostname == "" {
		hostname = r.URL.Query().Get("host")
	}
	if hostname == "" {
		// Try path: /jump/hostname.i2p
		path := strings.TrimPrefix(r.URL.Path, "/jump/")
		path = strings.TrimPrefix(path, "/")
		if path != "" {
			hostname = path
		}
	}

	if hostname == "" {
		s.renderError(w, "No hostname specified")
		return
	}

	// Normalize hostname
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".i2p") {
		hostname += ".i2p"
	}

	s.mu.Lock()
	s.lookups++
	s.mu.Unlock()

	// Look up the address
	dest, err := s.store.LookupB64(hostname)
	if err != nil {
		// Render a page with the error and option to add
		s.renderNotFound(w, hostname)
		return
	}

	// Render jump page
	tmpl := template.Must(template.New("jump").Parse(jumpTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"ServiceName": s.serviceName,
		"Hostname":    hostname,
		"Destination": dest,
	})
}

// handleAdd handles address additions.
func (s *Service) handleAdd(w http.ResponseWriter, r *http.Request) {
	if !s.allowAdd {
		s.renderError(w, "Address additions are disabled")
		return
	}

	if r.Method == http.MethodGet {
		// Show add form
		hostname := r.URL.Query().Get("host")
		tmpl := template.Must(template.New("add").Parse(addTemplate))
		tmpl.Execute(w, map[string]interface{}{
			"ServiceName": s.serviceName,
			"Hostname":    hostname,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data")
		return
	}

	hostname := strings.ToLower(strings.TrimSpace(r.FormValue("hostname")))
	dest := strings.TrimSpace(r.FormValue("destination"))

	if hostname == "" || dest == "" {
		s.renderError(w, "Hostname and destination are required")
		return
	}

	// Normalize hostname
	if !strings.HasSuffix(hostname, ".i2p") {
		hostname += ".i2p"
	}

	// Validate destination
	if len(dest) < 516 {
		s.renderError(w, "Invalid destination (too short)")
		return
	}

	// Add to store
	if err := s.store.Add(hostname, dest, false); err != nil {
		s.renderError(w, "Failed to add address: "+err.Error())
		return
	}

	s.mu.Lock()
	s.additions++
	s.mu.Unlock()

	// Show success
	s.renderSuccess(w, hostname)
}

// handleLookup handles address lookups.
func (s *Service) handleLookup(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		hostname = r.URL.Query().Get("a")
	}

	if hostname == "" {
		s.renderError(w, "No hostname specified")
		return
	}

	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".i2p") {
		hostname += ".i2p"
	}

	s.mu.Lock()
	s.lookups++
	s.mu.Unlock()

	dest, err := s.store.LookupB64(hostname)
	if err != nil {
		s.renderNotFound(w, hostname)
		return
	}

	// Show the destination
	tmpl := template.Must(template.New("lookup").Parse(lookupTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"ServiceName": s.serviceName,
		"Hostname":    hostname,
		"Destination": dest,
	})
}

// handleHostsTxt serves the address book in hosts.txt format.
func (s *Service) handleHostsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	filter := r.URL.Query().Get("filter")
	entries := s.store.List(filter)

	// Sort by hostname
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Hostname < entries[j].Hostname
	})

	fmt.Fprintf(w, "# I2P Address Book\n")
	fmt.Fprintf(w, "# Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# Entries: %d\n\n", len(entries))

	for _, entry := range entries {
		fmt.Fprintf(w, "%s=%s\n", entry.Hostname, entry.Destination)
	}
}

// handleAPILookup handles API lookups.
func (s *Service) handleAPILookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "No hostname specified",
		})
		return
	}

	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".i2p") {
		hostname += ".i2p"
	}

	s.mu.Lock()
	s.lookups++
	s.mu.Unlock()

	dest, err := s.store.LookupB64(hostname)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":    "Not found",
			"hostname": hostname,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname":    hostname,
		"destination": dest,
	})
}

// handleAPIAdd handles API additions.
func (s *Service) handleAPIAdd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !s.allowAdd {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Additions disabled",
		})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "POST required",
		})
		return
	}

	var req struct {
		Hostname    string `json:"hostname"`
		Destination string `json:"destination"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Invalid JSON",
		})
		return
	}

	hostname := strings.ToLower(strings.TrimSpace(req.Hostname))
	if !strings.HasSuffix(hostname, ".i2p") {
		hostname += ".i2p"
	}

	if err := s.store.Add(hostname, req.Destination, false); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	s.mu.Lock()
	s.additions++
	s.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"hostname": hostname,
	})
}

// handleAPIList handles API listing.
func (s *Service) handleAPIList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	filter := r.URL.Query().Get("filter")
	entries := s.store.List(filter)

	result := make([]map[string]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, map[string]string{
			"hostname":    entry.Hostname,
			"destination": entry.Destination,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(result),
		"entries": result,
	})
}

// renderError renders an error page.
func (s *Service) renderError(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusBadRequest)
	tmpl := template.Must(template.New("error").Parse(errorTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"ServiceName": s.serviceName,
		"Message":     message,
	})
}

// renderNotFound renders a not found page.
func (s *Service) renderNotFound(w http.ResponseWriter, hostname string) {
	w.WriteHeader(http.StatusNotFound)
	tmpl := template.Must(template.New("notfound").Parse(notFoundTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"ServiceName": s.serviceName,
		"Hostname":    hostname,
		"AllowAdd":    s.allowAdd,
	})
}

// renderSuccess renders a success page.
func (s *Service) renderSuccess(w http.ResponseWriter, hostname string) {
	tmpl := template.Must(template.New("success").Parse(successTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"ServiceName": s.serviceName,
		"Hostname":    hostname,
	})
}

// Stats returns service statistics.
func (s *Service) Stats() (lookups, additions int64, uptime time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lookups, s.additions, time.Since(s.startTime)
}

// Ensure url is imported
var _ = url.QueryEscape

// HTML Templates
const indexTemplate = `<!DOCTYPE html>
<html>
<head>
<title>{{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
h1 { color: #333; }
.form-group { margin: 20px 0; }
input[type="text"] { width: 400px; padding: 8px; font-size: 14px; }
button { padding: 8px 16px; font-size: 14px; cursor: pointer; }
.stats { color: #666; margin-top: 40px; }
</style>
</head>
<body>
<h1>{{.ServiceName}}</h1>
<p>This is an I2P jump service with {{.Count}} addresses in the database.</p>

<h2>Look up an address</h2>
<form method="GET" action="/jump">
<div class="form-group">
<input type="text" name="a" placeholder="Enter hostname (e.g., forum.i2p)">
<button type="submit">Jump</button>
</div>
</form>

{{if .AllowAdd}}
<h2>Add an address</h2>
<p><a href="/add">Add a new address to the database</a></p>
{{end}}

<h2>Downloads</h2>
<p><a href="/hosts.txt">Download hosts.txt</a></p>

<div class="stats">
<p>API endpoints: /api/lookup?host=, /api/add, /api/list</p>
</div>

<footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
<p>Powered by <a href="https://github.com/blubskye/i2p_go">i2p_go</a> - I2P Router Implementation in Go</p>
</footer>
</body>
</html>`

const jumpTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Jump to {{.Hostname}} - {{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
.destination { word-break: break-all; background: #f5f5f5; padding: 10px; font-family: monospace; font-size: 12px; }
</style>
</head>
<body>
<h1>{{.Hostname}}</h1>
<p>The destination for this hostname is:</p>
<div class="destination">{{.Destination}}</div>
<p style="margin-top: 20px;">
Add this to your address book:<br>
<code>{{.Hostname}}={{.Destination}}</code>
</p>
</body>
</html>`

const addTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Add Address - {{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
.form-group { margin: 20px 0; }
input[type="text"], textarea { width: 100%; padding: 8px; font-size: 14px; box-sizing: border-box; }
textarea { height: 100px; font-family: monospace; }
button { padding: 8px 16px; font-size: 14px; cursor: pointer; }
label { display: block; margin-bottom: 5px; font-weight: bold; }
</style>
</head>
<body>
<h1>Add Address</h1>
<form method="POST" action="/add">
<div class="form-group">
<label for="hostname">Hostname</label>
<input type="text" name="hostname" id="hostname" value="{{.Hostname}}" placeholder="example.i2p">
</div>
<div class="form-group">
<label for="destination">Base64 Destination</label>
<textarea name="destination" id="destination" placeholder="Paste the Base64 destination here..."></textarea>
</div>
<button type="submit">Add Address</button>
</form>
<p><a href="/">Back to home</a></p>
</body>
</html>`

const lookupTemplate = `<!DOCTYPE html>
<html>
<head>
<title>{{.Hostname}} - {{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
.destination { word-break: break-all; background: #f5f5f5; padding: 10px; font-family: monospace; font-size: 12px; }
</style>
</head>
<body>
<h1>{{.Hostname}}</h1>
<h2>Destination</h2>
<div class="destination">{{.Destination}}</div>
<p><a href="/">Back to home</a></p>
</body>
</html>`

const errorTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Error - {{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
.error { color: #c00; }
</style>
</head>
<body>
<h1 class="error">Error</h1>
<p>{{.Message}}</p>
<p><a href="/">Back to home</a></p>
</body>
</html>`

const notFoundTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Not Found - {{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
</style>
</head>
<body>
<h1>Address Not Found</h1>
<p>The hostname <b>{{.Hostname}}</b> was not found in the database.</p>
{{if .AllowAdd}}
<p><a href="/add?host={{.Hostname}}">Add this address</a></p>
{{end}}
<p><a href="/">Back to home</a></p>
</body>
</html>`

const successTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Success - {{.ServiceName}}</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
.success { color: #060; }
</style>
</head>
<body>
<h1 class="success">Success</h1>
<p>The address <b>{{.Hostname}}</b> has been added to the database.</p>
<p><a href="/lookup?host={{.Hostname}}">View the address</a></p>
<p><a href="/">Back to home</a></p>
</body>
</html>`
