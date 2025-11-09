package dns

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (nc *DNSCache) Name() string {
	return datastores.DNS
}

// GetHealth returns the current health status of the datastore
func (nc *DNSCache) GetHealth() *datastores.HealthInfo {
	// Try to acquire lock with retries to distinguish between busy (healthy) and deadlocked (unhealthy)
	const maxAttempts = 10
	const retryDelay = 10 * time.Millisecond // Total max wait: 100ms

	for attempt := range maxAttempts {
		if !nc.lock.TryRLock() {
			// Failed to acquire lock, retry if not last attempt
			if attempt < maxAttempts-1 {
				time.Sleep(retryDelay)
			}
			continue
		}

		// Verify LRU cache is healthy
		if nc.queryRoots == nil {
			nc.lock.RUnlock()
			return &datastores.HealthInfo{
				Status:    datastores.HealthUnhealthy,
				Message:   "query roots cache is nil",
				LastCheck: time.Now(),
			}
		}

		nc.lock.RUnlock()
		return &datastores.HealthInfo{
			Status:    datastores.HealthHealthy,
			Message:   "",
			LastCheck: time.Now(),
		}
	}

	// Failed to acquire lock after multiple attempts
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "unable to acquire lock after multiple attempts - possible deadlock or severe contention",
		LastCheck: time.Now(),
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
func (nc *DNSCache) GetDNSResponse(query string) (*datastores.DNSResponse, error) {
	nc.lastAccessNano.Store(time.Now().UnixNano())

	result, err := nc.Get(query)
	if err != nil {
		return nil, datastores.ErrNotFound
	}

	return &datastores.DNSResponse{
		Query:   query,
		IPs:     result.IPResults(),
		Domains: result.DNSResults(),
	}, nil
}
