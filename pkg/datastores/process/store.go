package process

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (pt *ProcessTree) Name() string {
	return datastores.Process
}

// GetHealth returns the current health status of the datastore
func (pt *ProcessTree) GetHealth() *datastores.HealthInfo {
	// Verify LRU caches are healthy
	if pt.processesLRU == nil || pt.threadsLRU == nil {
		return &datastores.HealthInfo{
			Status:    datastores.HealthUnhealthy,
			Message:   "LRU caches are not initialized",
			LastCheck: time.Now(),
		}
	}

	// Try to acquire locks with retries to distinguish between busy (healthy) and deadlocked (unhealthy)
	const maxAttempts = 10
	const retryDelay = 10 * time.Millisecond // Total max wait: 100ms

	// Try processesThreads lock
	for attempt := range maxAttempts {
		if !pt.processesThreadsMtx.TryRLock() {
			// Failed to acquire lock, retry if not last attempt
			if attempt < maxAttempts-1 {
				time.Sleep(retryDelay)
			}
			continue
		}
		_ = len(pt.processesThreads)
		pt.processesThreadsMtx.RUnlock()
		goto checkChildrenLock
	}
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "unable to acquire processesThreads lock after multiple attempts - possible deadlock",
		LastCheck: time.Now(),
	}

checkChildrenLock:
	// Try processesChildren lock
	for attempt := range maxAttempts {
		if !pt.processesChildrenMtx.TryRLock() {
			// Failed to acquire lock, retry if not last attempt
			if attempt < maxAttempts-1 {
				time.Sleep(retryDelay)
			}
			continue
		}
		_ = len(pt.processesChildren)
		pt.processesChildrenMtx.RUnlock()
		return &datastores.HealthInfo{
			Status:    datastores.HealthHealthy,
			Message:   "",
			LastCheck: time.Now(),
		}
	}
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "unable to acquire processesChildren lock after multiple attempts - possible deadlock",
		LastCheck: time.Now(),
	}
}

// GetMetrics returns operational metrics for the datastore
func (pt *ProcessTree) GetMetrics() *datastores.DataStoreMetrics {
	processCount := pt.processesLRU.Len()
	threadCount := pt.threadsLRU.Len()
	totalItems := int64(processCount + threadCount)
	lastAccessNano := pt.lastAccessNano.Load()

	return &datastores.DataStoreMetrics{
		ItemCount:    totalItems,
		SuccessCount: 0, // TODO: Track in Phase 2
		ErrorCount:   0, // TODO: Track in Phase 2
		CacheHits:    0, // TODO: Track in Phase 2
		CacheMisses:  0, // TODO: Track in Phase 2
		LastAccess:   time.Unix(0, lastAccessNano),
	}
}

// ProcessStore interface implementation

// GetProcess retrieves process information by entity ID (hash)
func (pt *ProcessTree) GetProcess(entityId uint64) (*datastores.ProcessInfo, bool) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	hash := uint32(entityId)
	proc, ok := pt.GetProcessByHash(hash)
	if !ok {
		return nil, false
	}

	info := proc.GetInfo()
	executable := proc.GetExecutable()

	return &datastores.ProcessInfo{
		EntityID:  entityId,
		PID:       uint32(info.GetPid()),
		PPID:      uint32(info.GetPPid()),
		Name:      info.GetName(),
		Exe:       executable.GetPath(),
		StartTime: info.GetStartTime(),
		UID:       info.GetUid(),
		GID:       info.GetGid(),
	}, true
}

// GetChildProcesses returns all child processes of the given process
func (pt *ProcessTree) GetChildProcesses(entityId uint64) ([]*datastores.ProcessInfo, error) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	hash := uint32(entityId)

	// Get child hashes using the internal method
	pt.processesChildrenMtx.RLock()
	childrenMap, ok := pt.processesChildren[hash]
	pt.processesChildrenMtx.RUnlock()

	if !ok {
		return []*datastores.ProcessInfo{}, nil
	}

	children := make([]*datastores.ProcessInfo, 0, len(childrenMap))
	for childHash := range childrenMap {
		if childInfo, ok := pt.GetProcess(uint64(childHash)); ok {
			children = append(children, childInfo)
		}
	}

	return children, nil
}
