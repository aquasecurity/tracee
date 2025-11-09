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
func (pt *ProcessTree) GetProcess(entityId uint32) (*datastores.ProcessInfo, error) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	hash := entityId
	proc, ok := pt.GetProcessByHash(hash)
	if !ok {
		return nil, datastores.ErrNotFound
	}

	info := proc.GetInfo()
	executable := proc.GetExecutable()

	return &datastores.ProcessInfo{
		UniqueId:       entityId,
		ParentUniqueId: proc.GetParentHash(),

		HostPid:  uint32(info.GetPid()),
		Pid:      uint32(info.GetNsPid()),
		HostPpid: uint32(info.GetPPid()),
		Ppid:     uint32(info.GetNsPPid()),

		Name:      info.GetName(),
		Exe:       executable.GetPath(),
		StartTime: info.GetStartTime(),
		ExitTime:  info.GetExitTime(),
		UID:       info.GetUid(),
		GID:       info.GetGid(),
	}, nil
}

// GetChildProcesses returns all child processes of the given process
func (pt *ProcessTree) GetChildProcesses(entityId uint32) ([]*datastores.ProcessInfo, error) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	hash := entityId

	// Get child hashes using the internal method
	pt.processesChildrenMtx.RLock()
	childrenMap, ok := pt.processesChildren[hash]
	pt.processesChildrenMtx.RUnlock()

	if !ok {
		return []*datastores.ProcessInfo{}, nil
	}

	children := make([]*datastores.ProcessInfo, 0, len(childrenMap))
	for childHash := range childrenMap {
		if childInfo, err := pt.GetProcess(childHash); err == nil {
			children = append(children, childInfo)
		}
	}

	return children, nil
}

// GetAncestry retrieves the process ancestry chain up to maxDepth levels
// Returns slice of ProcessInfo with [0] = process itself, [1] = parent, [2] = grandparent, etc.
// If a parent is not found in the tree, the chain stops there
func (pt *ProcessTree) GetAncestry(entityId uint32, maxDepth int) ([]*datastores.ProcessInfo, error) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	if maxDepth <= 0 {
		return []*datastores.ProcessInfo{}, nil
	}

	ancestry := make([]*datastores.ProcessInfo, 0, maxDepth)
	currentHash := entityId

	// Walk up the parent chain
	for i := 0; i < maxDepth; i++ {
		proc, ok := pt.GetProcessByHash(currentHash)
		if !ok {
			break // Process not in tree, stop here
		}

		info := proc.GetInfo()
		executable := proc.GetExecutable()
		parentHash := proc.GetParentHash()

		ancestry = append(ancestry, &datastores.ProcessInfo{
			UniqueId:       currentHash,
			ParentUniqueId: parentHash,

			HostPid:  uint32(info.GetPid()),
			Pid:      uint32(info.GetNsPid()),
			HostPpid: uint32(info.GetPPid()),
			Ppid:     uint32(info.GetNsPPid()),

			Name:      info.GetName(),
			Exe:       executable.GetPath(),
			StartTime: info.GetStartTime(),
			ExitTime:  info.GetExitTime(),
			UID:       info.GetUid(),
			GID:       info.GetGid(),
		})

		// Move to parent
		if parentHash == 0 || parentHash == currentHash {
			break // No parent or circular reference
		}
		currentHash = parentHash
	}

	return ancestry, nil
}
