package dns

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (nc *DNSCache) Name() string {
	return "dns"
}

// GetHealth returns the current health status of the datastore
func (nc *DNSCache) GetHealth() *datastores.HealthInfo {
	// Try to acquire read lock with timeout to detect deadlocks
	lockAcquired := make(chan struct{})
	go func() {
		nc.lock.RLock()
		_ = len(nc.queryIndices) // Read data to avoid empty critical section
		nc.lock.RUnlock()
		close(lockAcquired)
	}()

	select {
	case <-lockAcquired:
		// Verify LRU cache is healthy
		if nc.queryRoots == nil {
			return &datastores.HealthInfo{
				Status:    datastores.HealthUnhealthy,
				Message:   "query roots cache is nil",
				LastCheck: time.Now(),
			}
		}
		return &datastores.HealthInfo{
			Status:    datastores.HealthHealthy,
			Message:   "",
			LastCheck: time.Now(),
		}
	case <-time.After(100 * time.Millisecond):
		return &datastores.HealthInfo{
			Status:    datastores.HealthUnhealthy,
			Message:   "lock acquisition timeout - possible deadlock",
			LastCheck: time.Now(),
		}
	}
}

// GetMetrics returns operational metrics for the datastore
func (nc *DNSCache) GetMetrics() *datastores.DataStoreMetrics {
	itemCount := nc.queryRoots.Len()
	lastAccessNano := nc.lastAccessNano.Load()

	return &datastores.DataStoreMetrics{
		ItemCount:    int64(itemCount),
		SuccessCount: 0, // TODO: Track in Phase 2
		ErrorCount:   0, // TODO: Track in Phase 2
		CacheHits:    0, // TODO: Track in Phase 2
		CacheMisses:  0, // TODO: Track in Phase 2
		LastAccess:   time.Unix(0, lastAccessNano),
	}
}

// DNSStore interface implementation

// GetDNSResponse retrieves cached DNS response for a query
func (nc *DNSCache) GetDNSResponse(query string) (*datastores.DNSResponse, bool) {
	nc.lastAccessNano.Store(time.Now().UnixNano())

	result, err := nc.Get(query)
	if err != nil {
		return nil, false
	}

	return &datastores.DNSResponse{
		Query:   query,
		IPs:     result.IPResults(),
		Domains: result.DNSResults(),
	}, true
}
