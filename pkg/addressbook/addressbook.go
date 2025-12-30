// Package addressbook implements I2P address book functionality.
// It provides name resolution from .i2p hostnames to I2P destinations.
package addressbook

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Errors
var (
	ErrNotFound       = errors.New("addressbook: hostname not found")
	ErrInvalidEntry   = errors.New("addressbook: invalid entry")
	ErrAlreadyExists  = errors.New("addressbook: hostname already exists")
	ErrInvalidHostname = errors.New("addressbook: invalid hostname")
)

// Entry represents an address book entry.
type Entry struct {
	Hostname    string
	Destination string // Base64 encoded destination
	Added       time.Time
	Source      string // Where this entry came from
	Local       bool   // True if locally added
}

// Subscription represents a remote address book subscription.
type Subscription struct {
	URL         string
	Etag        string
	LastFetch   time.Time
	LastSuccess time.Time
	Enabled     bool
}

// AddressBook manages I2P hostname to destination mappings.
type AddressBook struct {
	mu sync.RWMutex

	// Storage paths
	dataDir     string
	hostsFile   string
	privateFile string
	subsFile    string

	// In-memory cache
	entries      map[string]*Entry
	subscriptions []*Subscription

	// Lookup function for destinations
	destLookup func(string) (*data.Destination, error)

	// HTTP client for fetching subscriptions (would use I2P in practice)
	httpClient *http.Client

	// Background update
	updateInterval time.Duration
	done           chan struct{}
	running        bool
}

// NewAddressBook creates a new address book.
func NewAddressBook(dataDir string) *AddressBook {
	return &AddressBook{
		dataDir:        dataDir,
		hostsFile:      filepath.Join(dataDir, "hosts.txt"),
		privateFile:    filepath.Join(dataDir, "privatehosts.txt"),
		subsFile:       filepath.Join(dataDir, "subscriptions.txt"),
		entries:        make(map[string]*Entry),
		subscriptions:  make([]*Subscription, 0),
		httpClient:     &http.Client{Timeout: 60 * time.Second},
		updateInterval: 1 * time.Hour,
		done:           make(chan struct{}),
	}
}

// Load loads the address book from disk.
func (ab *AddressBook) Load() error {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Ensure directory exists
	if err := os.MkdirAll(ab.dataDir, 0755); err != nil {
		return err
	}

	// Load main hosts file
	if err := ab.loadHostsFile(ab.hostsFile, false); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Load private hosts file
	if err := ab.loadHostsFile(ab.privateFile, true); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Load subscriptions
	if err := ab.loadSubscriptions(); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// loadHostsFile loads entries from a hosts.txt format file.
func (ab *AddressBook) loadHostsFile(path string, local bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	source := "hosts.txt"
	if local {
		source = "private"
	}

	return ab.parseHostsReader(file, source, local)
}

// parseHostsReader parses hosts.txt format from a reader.
func (ab *AddressBook) parseHostsReader(r io.Reader, source string, local bool) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hostname=destination
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		hostname := normalizeHostname(strings.TrimSpace(parts[0]))
		destB64 := strings.TrimSpace(parts[1])

		// Validate destination
		if !isValidDestination(destB64) {
			continue
		}

		// Don't overwrite local entries with remote ones
		if existing, ok := ab.entries[hostname]; ok && existing.Local && !local {
			continue
		}

		ab.entries[hostname] = &Entry{
			Hostname:    hostname,
			Destination: destB64,
			Added:       time.Now(),
			Source:      source,
			Local:       local,
		}
	}

	return scanner.Err()
}

// loadSubscriptions loads subscription configuration.
func (ab *AddressBook) loadSubscriptions() error {
	file, err := os.Open(ab.subsFile)
	if err != nil {
		// Create default subscriptions
		ab.subscriptions = DefaultSubscriptions()
		return ab.saveSubscriptions()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ab.subscriptions = append(ab.subscriptions, &Subscription{
			URL:     line,
			Enabled: true,
		})
	}

	return scanner.Err()
}

// saveSubscriptions saves subscription configuration.
func (ab *AddressBook) saveSubscriptions() error {
	file, err := os.Create(ab.subsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("# I2P Address Book Subscriptions\n")
	file.WriteString("# One URL per line\n\n")

	for _, sub := range ab.subscriptions {
		if sub.Enabled {
			file.WriteString(sub.URL + "\n")
		}
	}

	return nil
}

// Save saves the address book to disk.
func (ab *AddressBook) Save() error {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	// Save main hosts file
	if err := ab.saveHostsFile(ab.hostsFile, false); err != nil {
		return err
	}

	// Save private hosts file
	if err := ab.saveHostsFile(ab.privateFile, true); err != nil {
		return err
	}

	return nil
}

// saveHostsFile saves entries to a hosts.txt format file.
func (ab *AddressBook) saveHostsFile(path string, localOnly bool) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	if localOnly {
		file.WriteString("# I2P Private Address Book\n")
		file.WriteString("# Local entries that override subscriptions\n\n")
	} else {
		file.WriteString("# I2P Address Book\n")
		file.WriteString("# Format: hostname=base64destination\n\n")
	}

	// Sort hostnames for consistent output
	hostnames := make([]string, 0, len(ab.entries))
	for hostname := range ab.entries {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	for _, hostname := range hostnames {
		entry := ab.entries[hostname]
		if localOnly && !entry.Local {
			continue
		}
		if !localOnly && entry.Local {
			continue
		}
		file.WriteString(fmt.Sprintf("%s=%s\n", entry.Hostname, entry.Destination))
	}

	return nil
}

// Lookup looks up a hostname and returns the destination.
func (ab *AddressBook) Lookup(hostname string) (*data.Destination, error) {
	hostname = normalizeHostname(hostname)

	ab.mu.RLock()
	entry, ok := ab.entries[hostname]
	ab.mu.RUnlock()

	if !ok {
		return nil, ErrNotFound
	}

	// Decode the destination
	destBytes, err := data.Base64Decode(entry.Destination)
	if err != nil {
		return nil, err
	}

	return data.NewDestination(destBytes)
}

// LookupB64 looks up a hostname and returns the Base64 destination.
func (ab *AddressBook) LookupB64(hostname string) (string, error) {
	hostname = normalizeHostname(hostname)

	ab.mu.RLock()
	entry, ok := ab.entries[hostname]
	ab.mu.RUnlock()

	if !ok {
		return "", ErrNotFound
	}

	return entry.Destination, nil
}

// ReverseLookup finds the hostname for a destination hash.
func (ab *AddressBook) ReverseLookup(hash data.IdentHash) (string, error) {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	hashStr := data.Base32Encode(hash[:])

	for _, entry := range ab.entries {
		destBytes, err := data.Base64Decode(entry.Destination)
		if err != nil {
			continue
		}

		dest, err := data.NewDestination(destBytes)
		if err != nil {
			continue
		}

		destHash := dest.GetIdentHash()
		if data.Base32Encode(destHash[:]) == hashStr {
			return entry.Hostname, nil
		}
	}

	return "", ErrNotFound
}

// Add adds a new hostname to destination mapping.
func (ab *AddressBook) Add(hostname, destB64 string, local bool) error {
	hostname = normalizeHostname(hostname)

	if !isValidHostname(hostname) {
		return ErrInvalidHostname
	}

	if !isValidDestination(destB64) {
		return ErrInvalidEntry
	}

	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Check if already exists
	if existing, ok := ab.entries[hostname]; ok {
		if existing.Local && !local {
			return ErrAlreadyExists
		}
	}

	ab.entries[hostname] = &Entry{
		Hostname:    hostname,
		Destination: destB64,
		Added:       time.Now(),
		Source:      "local",
		Local:       local,
	}

	return nil
}

// Remove removes a hostname from the address book.
func (ab *AddressBook) Remove(hostname string) error {
	hostname = normalizeHostname(hostname)

	ab.mu.Lock()
	defer ab.mu.Unlock()

	if _, ok := ab.entries[hostname]; !ok {
		return ErrNotFound
	}

	delete(ab.entries, hostname)
	return nil
}

// List returns all entries matching the filter.
func (ab *AddressBook) List(filter string) []*Entry {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	result := make([]*Entry, 0)
	filter = strings.ToLower(filter)

	for _, entry := range ab.entries {
		if filter == "" || strings.Contains(strings.ToLower(entry.Hostname), filter) {
			result = append(result, entry)
		}
	}

	// Sort by hostname
	sort.Slice(result, func(i, j int) bool {
		return result[i].Hostname < result[j].Hostname
	})

	return result
}

// Count returns the number of entries.
func (ab *AddressBook) Count() int {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return len(ab.entries)
}

// Start starts the background subscription updater.
func (ab *AddressBook) Start() {
	ab.mu.Lock()
	if ab.running {
		ab.mu.Unlock()
		return
	}
	ab.running = true
	ab.mu.Unlock()

	go ab.updateLoop()
}

// Stop stops the background updater.
func (ab *AddressBook) Stop() {
	ab.mu.Lock()
	if !ab.running {
		ab.mu.Unlock()
		return
	}
	ab.running = false
	close(ab.done)
	ab.mu.Unlock()
}

// updateLoop periodically fetches subscription updates.
func (ab *AddressBook) updateLoop() {
	// Initial fetch
	ab.fetchSubscriptions()

	ticker := time.NewTicker(ab.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ab.done:
			return
		case <-ticker.C:
			ab.fetchSubscriptions()
		}
	}
}

// fetchSubscriptions fetches all enabled subscriptions.
func (ab *AddressBook) fetchSubscriptions() {
	ab.mu.RLock()
	subs := make([]*Subscription, len(ab.subscriptions))
	copy(subs, ab.subscriptions)
	ab.mu.RUnlock()

	for _, sub := range subs {
		if !sub.Enabled {
			continue
		}

		if err := ab.fetchSubscription(sub); err != nil {
			// Log error but continue
			continue
		}
	}

	// Save after updates
	ab.Save()
}

// fetchSubscription fetches a single subscription.
func (ab *AddressBook) fetchSubscription(sub *Subscription) error {
	req, err := http.NewRequest("GET", sub.URL, nil)
	if err != nil {
		return err
	}

	// Use ETag for conditional fetching
	if sub.Etag != "" {
		req.Header.Set("If-None-Match", sub.Etag)
	}

	resp, err := ab.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	sub.LastFetch = time.Now()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Update ETag
	sub.Etag = resp.Header.Get("ETag")
	sub.LastSuccess = time.Now()

	// Parse the response
	ab.mu.Lock()
	defer ab.mu.Unlock()

	return ab.parseHostsReader(resp.Body, sub.URL, false)
}

// AddSubscription adds a new subscription.
func (ab *AddressBook) AddSubscription(url string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Check if already exists
	for _, sub := range ab.subscriptions {
		if sub.URL == url {
			sub.Enabled = true
			return
		}
	}

	ab.subscriptions = append(ab.subscriptions, &Subscription{
		URL:     url,
		Enabled: true,
	})

	ab.saveSubscriptions()
}

// RemoveSubscription removes a subscription.
func (ab *AddressBook) RemoveSubscription(url string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	for i, sub := range ab.subscriptions {
		if sub.URL == url {
			ab.subscriptions = append(ab.subscriptions[:i], ab.subscriptions[i+1:]...)
			break
		}
	}

	ab.saveSubscriptions()
}

// GetSubscriptions returns all subscriptions.
func (ab *AddressBook) GetSubscriptions() []*Subscription {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	result := make([]*Subscription, len(ab.subscriptions))
	copy(result, ab.subscriptions)
	return result
}

// DefaultSubscriptions returns the default subscription list.
func DefaultSubscriptions() []*Subscription {
	return []*Subscription{
		{URL: "http://i2p-projekt.i2p/hosts.txt", Enabled: true},
		{URL: "http://stats.i2p/cgi-bin/newhosts.txt", Enabled: true},
		{URL: "http://no.i2p/export/hosts.txt", Enabled: true},
	}
}

// normalizeHostname normalizes a hostname.
func normalizeHostname(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	// Remove trailing .i2p if present for lookup, but keep for storage
	// Actually, always ensure .i2p suffix
	if !strings.HasSuffix(hostname, ".i2p") {
		hostname += ".i2p"
	}

	return hostname
}

// isValidHostname checks if a hostname is valid.
func isValidHostname(hostname string) bool {
	if len(hostname) < 5 || len(hostname) > 67 { // minimum: "a.i2p", max: 63 + ".i2p"
		return false
	}

	if !strings.HasSuffix(hostname, ".i2p") {
		return false
	}

	// Check for valid characters
	name := strings.TrimSuffix(hostname, ".i2p")
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}

	return true
}

// isValidDestination checks if a Base64 destination is valid.
func isValidDestination(destB64 string) bool {
	if len(destB64) < 516 { // Minimum destination size in Base64
		return false
	}

	// Try to decode
	decoded, err := data.Base64Decode(destB64)
	if err != nil {
		return false
	}

	// Try to parse as destination
	_, err = data.NewDestination(decoded)
	return err == nil
}

// Import imports entries from a hosts.txt format string.
func (ab *AddressBook) Import(content string) (int, error) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	reader := strings.NewReader(content)
	countBefore := len(ab.entries)

	err := ab.parseHostsReader(reader, "import", false)
	if err != nil {
		return 0, err
	}

	return len(ab.entries) - countBefore, nil
}

// Export exports all entries as hosts.txt format.
func (ab *AddressBook) Export() string {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("# I2P Address Book Export\n")
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("# Entries: %d\n\n", len(ab.entries)))

	hostnames := make([]string, 0, len(ab.entries))
	for hostname := range ab.entries {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	for _, hostname := range hostnames {
		entry := ab.entries[hostname]
		sb.WriteString(fmt.Sprintf("%s=%s\n", entry.Hostname, entry.Destination))
	}

	return sb.String()
}
