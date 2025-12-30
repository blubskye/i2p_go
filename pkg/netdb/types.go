// Package netdb implements the I2P network database.
// The network database is a distributed Kademlia DHT that stores
// RouterInfo and LeaseSet entries.
package netdb

import (
	"errors"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// NetDb constants
const (
	// Kademlia parameters
	KBucketSize      = 20   // Max entries per bucket
	NumKBuckets      = 256  // 256 bits in hash
	AlphaParallelism = 3    // Concurrent lookups
	MaxClosestNodes  = 8    // Closest nodes to return

	// Timeouts and intervals
	LookupTimeout     = 30 * time.Second
	StoreTimeout      = 30 * time.Second
	RefreshInterval   = 60 * time.Minute
	CleanupInterval   = 10 * time.Minute
	RouterInfoExpiry  = 60 * time.Minute
	LeaseSetExpiry    = 10 * time.Minute

	// Entry types
	EntryTypeRouterInfo = 0
	EntryTypeLeaseSet   = 1
	EntryTypeLeaseSet2  = 3

	// Lookup flags
	LookupFlagDeliveryTypeDirect = 0x00
	LookupFlagDeliveryTypeTunnel = 0x01
	LookupFlagEncryptionType     = 0x02
	LookupFlagReplyTunnelFlag    = 0x04
)

// Entry represents a database entry (RouterInfo or LeaseSet).
type Entry interface {
	Hash() data.Hash
	Type() int
	Data() []byte
	PublishTime() time.Time
	IsExpired() bool
}

// RouterInfoEntry wraps a RouterInfo for the database.
type RouterInfoEntry struct {
	Info        *data.RouterInfo
	ReceivedAt  time.Time
	PublishedAt time.Time
}

// Hash returns the identity hash.
func (e *RouterInfoEntry) Hash() data.Hash {
	return e.Info.GetIdentHash()
}

// Type returns the entry type.
func (e *RouterInfoEntry) Type() int {
	return EntryTypeRouterInfo
}

// Data returns the serialized RouterInfo.
func (e *RouterInfoEntry) Data() []byte {
	return e.Info.ToBuffer()
}

// PublishTime returns when the entry was published.
func (e *RouterInfoEntry) PublishTime() time.Time {
	return e.PublishedAt
}

// IsExpired returns true if the entry has expired.
func (e *RouterInfoEntry) IsExpired() bool {
	return time.Since(e.ReceivedAt) > RouterInfoExpiry
}

// LeaseSetEntry wraps a LeaseSet for the database.
type LeaseSetEntry struct {
	LeaseSet    data.DatabaseEntry
	ReceivedAt  time.Time
	PublishedAt time.Time
}

// Hash returns the destination hash.
func (e *LeaseSetEntry) Hash() data.Hash {
	return e.LeaseSet.GetIdentHash()
}

// Type returns the entry type.
func (e *LeaseSetEntry) Type() int {
	return EntryTypeLeaseSet
}

// Data returns the serialized LeaseSet.
func (e *LeaseSetEntry) Data() []byte {
	return e.LeaseSet.ToBuffer()
}

// PublishTime returns when the entry was published.
func (e *LeaseSetEntry) PublishTime() time.Time {
	return e.PublishedAt
}

// IsExpired returns true if the entry has expired.
func (e *LeaseSetEntry) IsExpired() bool {
	return time.Since(e.ReceivedAt) > LeaseSetExpiry
}

// KBucket represents a Kademlia bucket containing nodes at a specific distance.
type KBucket struct {
	mu    sync.RWMutex
	nodes []*data.RouterInfo
}

// NewKBucket creates a new K-bucket.
func NewKBucket() *KBucket {
	return &KBucket{
		nodes: make([]*data.RouterInfo, 0, KBucketSize),
	}
}

// Add adds a node to the bucket.
func (b *KBucket) Add(node *data.RouterInfo) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	hash := node.GetIdentHash()

	// Check if already exists
	for i, existing := range b.nodes {
		if existing.GetIdentHash() == hash {
			// Move to end (most recently seen)
			b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
			b.nodes = append(b.nodes, node)
			return true
		}
	}

	// Add if not full
	if len(b.nodes) < KBucketSize {
		b.nodes = append(b.nodes, node)
		return true
	}

	return false
}

// Remove removes a node from the bucket.
func (b *KBucket) Remove(hash data.Hash) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, node := range b.nodes {
		if node.GetIdentHash() == hash {
			b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
			return true
		}
	}
	return false
}

// Get returns a node by hash.
func (b *KBucket) Get(hash data.Hash) *data.RouterInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, node := range b.nodes {
		if node.GetIdentHash() == hash {
			return node
		}
	}
	return nil
}

// Size returns the number of nodes in the bucket.
func (b *KBucket) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.nodes)
}

// Nodes returns all nodes in the bucket.
func (b *KBucket) Nodes() []*data.RouterInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*data.RouterInfo, len(b.nodes))
	copy(result, b.nodes)
	return result
}

// LookupResult represents the result of a database lookup.
type LookupResult struct {
	Entry       Entry
	CloserPeers []data.Hash
	Found       bool
	FromPeer    data.Hash
}

// StoreResult represents the result of a database store.
type StoreResult struct {
	Success  bool
	Stored   int
	Failed   int
	FromPeer data.Hash
}

// Errors
var (
	ErrNotFound        = errors.New("netdb: entry not found")
	ErrInvalidEntry    = errors.New("netdb: invalid entry")
	ErrExpiredEntry    = errors.New("netdb: entry expired")
	ErrLookupFailed    = errors.New("netdb: lookup failed")
	ErrStoreFailed     = errors.New("netdb: store failed")
	ErrNoFloodfills    = errors.New("netdb: no floodfill routers available")
	ErrDatabaseClosed  = errors.New("netdb: database closed")
)
