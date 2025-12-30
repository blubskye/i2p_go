package netdb

import (
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
	"github.com/go-i2p/go-i2p/pkg/i2np"
)

// NetDb is the network database.
type NetDb struct {
	mu sync.RWMutex

	localIdentity data.Hash

	// RouterInfo storage
	routerInfos map[data.Hash]*RouterInfoEntry

	// LeaseSet storage
	leaseSets map[data.Hash]*LeaseSetEntry

	// K-buckets for Kademlia routing
	kBuckets [NumKBuckets]*KBucket

	// Floodfill routers
	floodfills map[data.Hash]*data.RouterInfo

	// Pending lookups
	pendingLookups map[uint32]*PendingLookup

	// Message sending function
	onSendMessage func(dest data.Hash, msg *i2np.RawMessage) error

	// Storage path for persistence
	storagePath string

	running bool
	done    chan struct{}
}

// PendingLookup represents an ongoing lookup.
type PendingLookup struct {
	Key        data.Hash
	OnComplete func(*LookupResult)
	StartTime  time.Time
	Queried    map[data.Hash]bool
}

// NewNetDb creates a new network database.
func NewNetDb(localIdentity data.Hash, storagePath string) *NetDb {
	ndb := &NetDb{
		localIdentity:  localIdentity,
		routerInfos:    make(map[data.Hash]*RouterInfoEntry),
		leaseSets:      make(map[data.Hash]*LeaseSetEntry),
		floodfills:     make(map[data.Hash]*data.RouterInfo),
		pendingLookups: make(map[uint32]*PendingLookup),
		storagePath:    storagePath,
		done:           make(chan struct{}),
	}

	// Initialize K-buckets
	for i := 0; i < NumKBuckets; i++ {
		ndb.kBuckets[i] = NewKBucket()
	}

	return ndb
}

// SetMessageSender sets the function for sending I2NP messages.
func (ndb *NetDb) SetMessageSender(sender func(dest data.Hash, msg *i2np.RawMessage) error) {
	ndb.onSendMessage = sender
}

// Start starts the network database.
func (ndb *NetDb) Start() error {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	if ndb.running {
		return nil
	}

	// Load from disk
	if ndb.storagePath != "" {
		ndb.loadFromDisk()
	}

	ndb.running = true

	// Start maintenance routines
	go ndb.maintenance()

	return nil
}

// Stop stops the network database.
func (ndb *NetDb) Stop() {
	ndb.mu.Lock()
	if !ndb.running {
		ndb.mu.Unlock()
		return
	}
	ndb.running = false
	close(ndb.done)
	ndb.mu.Unlock()

	// Save to disk
	if ndb.storagePath != "" {
		ndb.saveToDisk()
	}
}

// StoreRouterInfo stores a RouterInfo in the database.
func (ndb *NetDb) StoreRouterInfo(ri *data.RouterInfo) error {
	if ri == nil {
		return ErrInvalidEntry
	}

	hash := ri.GetIdentHash()

	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	entry := &RouterInfoEntry{
		Info:        ri,
		ReceivedAt:  time.Now(),
		PublishedAt: time.Now(), // Would extract from RouterInfo
	}

	ndb.routerInfos[hash] = entry

	// Add to K-bucket
	bucketIdx := ndb.getBucketIndex(hash)
	if bucketIdx >= 0 && bucketIdx < NumKBuckets {
		ndb.kBuckets[bucketIdx].Add(ri)
	}

	// Check if floodfill
	if ri.IsFloodfill() {
		ndb.floodfills[hash] = ri
	}

	return nil
}

// GetRouterInfo retrieves a RouterInfo from the database.
func (ndb *NetDb) GetRouterInfo(hash data.Hash) (*data.RouterInfo, error) {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	entry, ok := ndb.routerInfos[hash]
	if !ok {
		return nil, ErrNotFound
	}

	if entry.IsExpired() {
		return nil, ErrExpiredEntry
	}

	return entry.Info, nil
}

// StoreLeaseSet stores a LeaseSet in the database.
func (ndb *NetDb) StoreLeaseSet(ls data.DatabaseEntry) error {
	if ls == nil {
		return ErrInvalidEntry
	}

	hash := ls.GetIdentHash()

	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	entry := &LeaseSetEntry{
		LeaseSet:    ls,
		ReceivedAt:  time.Now(),
		PublishedAt: time.Now(),
	}

	ndb.leaseSets[hash] = entry

	return nil
}

// GetLeaseSet retrieves a LeaseSet from the database.
func (ndb *NetDb) GetLeaseSet(hash data.Hash) (data.DatabaseEntry, error) {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	entry, ok := ndb.leaseSets[hash]
	if !ok {
		return nil, ErrNotFound
	}

	if entry.IsExpired() {
		return nil, ErrExpiredEntry
	}

	return entry.LeaseSet, nil
}

// LookupRouterInfo looks up a RouterInfo, querying the network if needed.
func (ndb *NetDb) LookupRouterInfo(hash data.Hash, onComplete func(*data.RouterInfo, error)) {
	// First check local database
	ri, err := ndb.GetRouterInfo(hash)
	if err == nil {
		onComplete(ri, nil)
		return
	}

	// Query the network
	ndb.queryNetwork(hash, func(result *LookupResult) {
		if result.Found {
			if riEntry, ok := result.Entry.(*RouterInfoEntry); ok {
				onComplete(riEntry.Info, nil)
				return
			}
		}
		onComplete(nil, ErrLookupFailed)
	})
}

// LookupLeaseSet looks up a LeaseSet, querying the network if needed.
func (ndb *NetDb) LookupLeaseSet(hash data.Hash, onComplete func(data.DatabaseEntry, error)) {
	// First check local database
	ls, err := ndb.GetLeaseSet(hash)
	if err == nil {
		onComplete(ls, nil)
		return
	}

	// Query the network
	ndb.queryNetwork(hash, func(result *LookupResult) {
		if result.Found {
			if lsEntry, ok := result.Entry.(*LeaseSetEntry); ok {
				onComplete(lsEntry.LeaseSet, nil)
				return
			}
		}
		onComplete(nil, ErrLookupFailed)
	})
}

// queryNetwork queries the network for an entry.
func (ndb *NetDb) queryNetwork(hash data.Hash, onComplete func(*LookupResult)) {
	// Find closest floodfill routers
	floodfills := ndb.getClosestFloodfills(hash, AlphaParallelism)
	if len(floodfills) == 0 {
		onComplete(&LookupResult{Found: false})
		return
	}

	// Create lookup message
	lookupMsg := i2np.NewDatabaseLookup(hash, ndb.localIdentity, 0)

	// Send to floodfills
	for _, ff := range floodfills {
		if ndb.onSendMessage != nil {
			ndb.onSendMessage(ff.GetIdentHash(), lookupMsg.ToRawMessage())
		}
	}

	// Set up timeout
	go func() {
		time.Sleep(LookupTimeout)
		onComplete(&LookupResult{Found: false})
	}()
}

// PublishRouterInfo publishes our RouterInfo to floodfills.
func (ndb *NetDb) PublishRouterInfo(ri *data.RouterInfo) error {
	// Store locally
	if err := ndb.StoreRouterInfo(ri); err != nil {
		return err
	}

	// Get closest floodfills
	hash := ri.GetIdentHash()
	floodfills := ndb.getClosestFloodfills(hash, MaxClosestNodes)

	if len(floodfills) == 0 {
		return ErrNoFloodfills
	}

	// Create store message
	storeMsg := i2np.NewDatabaseStore(hash, 0, ri.ToBuffer())

	// Send to floodfills
	for _, ff := range floodfills {
		if ndb.onSendMessage != nil {
			ndb.onSendMessage(ff.GetIdentHash(), storeMsg.ToRawMessage())
		}
	}

	return nil
}

// PublishLeaseSet publishes a LeaseSet to floodfills.
func (ndb *NetDb) PublishLeaseSet(ls data.DatabaseEntry) error {
	// Store locally
	if err := ndb.StoreLeaseSet(ls); err != nil {
		return err
	}

	// Get closest floodfills
	hash := ls.GetIdentHash()
	floodfills := ndb.getClosestFloodfills(hash, MaxClosestNodes)

	if len(floodfills) == 0 {
		return ErrNoFloodfills
	}

	// Create store message
	storeMsg := i2np.NewDatabaseStore(hash, EntryTypeLeaseSet, ls.ToBuffer())

	// Send to floodfills
	for _, ff := range floodfills {
		if ndb.onSendMessage != nil {
			ndb.onSendMessage(ff.GetIdentHash(), storeMsg.ToRawMessage())
		}
	}

	return nil
}

// HandleDatabaseStore handles an incoming DatabaseStore message.
func (ndb *NetDb) HandleDatabaseStore(msg *i2np.DatabaseStore) error {
	switch msg.StoreType {
	case EntryTypeRouterInfo:
		ri, err := data.NewRouterInfo(msg.Data)
		if err != nil {
			return err
		}
		return ndb.StoreRouterInfo(ri)

	case EntryTypeLeaseSet:
		// Parse as LeaseSet v1
		ls, err := data.NewLeaseSet(msg.Data)
		if err != nil {
			return err
		}
		return ndb.StoreLeaseSet(ls)

	case EntryTypeLeaseSet2:
		// Parse as LeaseSet v2
		ls, err := data.NewLeaseSet2(msg.Data)
		if err != nil {
			return err
		}
		return ndb.StoreLeaseSet(ls)
	}

	return ErrInvalidEntry
}

// HandleDatabaseLookup handles an incoming DatabaseLookup message.
func (ndb *NetDb) HandleDatabaseLookup(msg *i2np.DatabaseLookup) (*i2np.DatabaseSearchReply, error) {
	hash := msg.Key

	// Check for RouterInfo
	ri, err := ndb.GetRouterInfo(hash)
	if err == nil {
		storeMsg := i2np.NewDatabaseStore(hash, EntryTypeRouterInfo, ri.ToBuffer())
		if ndb.onSendMessage != nil {
			ndb.onSendMessage(msg.From, storeMsg.ToRawMessage())
		}
		return nil, nil
	}

	// Check for LeaseSet
	ls, err := ndb.GetLeaseSet(hash)
	if err == nil {
		storeMsg := i2np.NewDatabaseStore(hash, EntryTypeLeaseSet, ls.ToBuffer())
		if ndb.onSendMessage != nil {
			ndb.onSendMessage(msg.From, storeMsg.ToRawMessage())
		}
		return nil, nil
	}

	// Not found - return closest peers
	closestPeers := ndb.getClosestRouters(hash, MaxClosestNodes)
	peerHashes := make([]data.Hash, len(closestPeers))
	for i, peer := range closestPeers {
		peerHashes[i] = peer.GetIdentHash()
	}

	return i2np.NewDatabaseSearchReply(hash, ndb.localIdentity, peerHashes), nil
}

// HandleDatabaseSearchReply handles an incoming DatabaseSearchReply message.
func (ndb *NetDb) HandleDatabaseSearchReply(msg *i2np.DatabaseSearchReply) {
	// Add peers to routing table
	for _, peerHash := range msg.PeerHashes {
		// Would need to look up RouterInfo for these peers
		// and add to K-buckets
		_ = peerHash
	}
}

// getClosestFloodfills returns the closest floodfill routers to a key.
func (ndb *NetDb) getClosestFloodfills(key data.Hash, count int) []*data.RouterInfo {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	if len(ndb.floodfills) == 0 {
		return nil
	}

	// Simple implementation - would use XOR distance for proper Kademlia
	result := make([]*data.RouterInfo, 0, count)
	for _, ff := range ndb.floodfills {
		result = append(result, ff)
		if len(result) >= count {
			break
		}
	}

	return result
}

// getClosestRouters returns the closest routers to a key.
func (ndb *NetDb) getClosestRouters(key data.Hash, count int) []*data.RouterInfo {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	result := make([]*data.RouterInfo, 0, count)

	// Get from K-bucket at the key's distance
	bucketIdx := ndb.getBucketIndex(key)

	// First, try the bucket at that distance
	if bucketIdx >= 0 && bucketIdx < NumKBuckets {
		nodes := ndb.kBuckets[bucketIdx].Nodes()
		for _, node := range nodes {
			result = append(result, node)
			if len(result) >= count {
				return result
			}
		}
	}

	// Expand to nearby buckets
	for i := 1; len(result) < count && i < NumKBuckets; i++ {
		// Check higher bucket
		if bucketIdx+i < NumKBuckets {
			nodes := ndb.kBuckets[bucketIdx+i].Nodes()
			for _, node := range nodes {
				result = append(result, node)
				if len(result) >= count {
					return result
				}
			}
		}
		// Check lower bucket
		if bucketIdx-i >= 0 {
			nodes := ndb.kBuckets[bucketIdx-i].Nodes()
			for _, node := range nodes {
				result = append(result, node)
				if len(result) >= count {
					return result
				}
			}
		}
	}

	return result
}

// getBucketIndex returns the K-bucket index for a key.
func (ndb *NetDb) getBucketIndex(key data.Hash) int {
	// XOR with our identity and find highest bit
	distance := key.XOR(ndb.localIdentity)

	// Find the highest set bit
	for i := 0; i < 32; i++ {
		if distance[i] != 0 {
			// Find highest bit in this byte
			b := distance[i]
			for j := 7; j >= 0; j-- {
				if (b & (1 << j)) != 0 {
					return i*8 + (7 - j)
				}
			}
		}
	}

	return 255 // Same as us (or very close)
}

// maintenance performs periodic database maintenance.
func (ndb *NetDb) maintenance() {
	cleanupTicker := time.NewTicker(CleanupInterval)
	refreshTicker := time.NewTicker(RefreshInterval)
	defer cleanupTicker.Stop()
	defer refreshTicker.Stop()

	for {
		select {
		case <-ndb.done:
			return

		case <-cleanupTicker.C:
			ndb.cleanupExpired()

		case <-refreshTicker.C:
			ndb.refreshKBuckets()
		}
	}
}

// cleanupExpired removes expired entries.
func (ndb *NetDb) cleanupExpired() {
	ndb.mu.Lock()
	defer ndb.mu.Unlock()

	// Cleanup RouterInfos
	for hash, entry := range ndb.routerInfos {
		if entry.IsExpired() {
			delete(ndb.routerInfos, hash)
			delete(ndb.floodfills, hash)
		}
	}

	// Cleanup LeaseSets
	for hash, entry := range ndb.leaseSets {
		if entry.IsExpired() {
			delete(ndb.leaseSets, hash)
		}
	}
}

// refreshKBuckets refreshes stale K-buckets.
func (ndb *NetDb) refreshKBuckets() {
	// Would query random keys in each bucket to refresh
}

// loadFromDisk loads the database from disk.
func (ndb *NetDb) loadFromDisk() {
	// Would load RouterInfo files from storage path
}

// saveToDisk saves the database to disk.
func (ndb *NetDb) saveToDisk() {
	// Would save RouterInfo files to storage path
}

// RouterInfoCount returns the number of RouterInfo entries.
func (ndb *NetDb) RouterInfoCount() int {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()
	return len(ndb.routerInfos)
}

// LeaseSetCount returns the number of LeaseSet entries.
func (ndb *NetDb) LeaseSetCount() int {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()
	return len(ndb.leaseSets)
}

// FloodfillCount returns the number of known floodfill routers.
func (ndb *NetDb) FloodfillCount() int {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()
	return len(ndb.floodfills)
}

// AllRouterInfos returns all RouterInfo entries.
func (ndb *NetDb) AllRouterInfos() []*data.RouterInfo {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	result := make([]*data.RouterInfo, 0, len(ndb.routerInfos))
	for _, entry := range ndb.routerInfos {
		if !entry.IsExpired() {
			result = append(result, entry.Info)
		}
	}
	return result
}

// RandomRouters returns random routers from the database.
func (ndb *NetDb) RandomRouters(count int, exclude []data.Hash) []*data.RouterInfo {
	ndb.mu.RLock()
	defer ndb.mu.RUnlock()

	excludeMap := make(map[data.Hash]bool)
	for _, h := range exclude {
		excludeMap[h] = true
	}

	result := make([]*data.RouterInfo, 0, count)
	for _, entry := range ndb.routerInfos {
		if !entry.IsExpired() && !excludeMap[entry.Hash()] {
			result = append(result, entry.Info)
			if len(result) >= count {
				break
			}
		}
	}

	return result
}
