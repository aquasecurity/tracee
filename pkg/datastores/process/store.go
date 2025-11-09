package process

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (pt *ProcessTree) Name() string {
	return "process"
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

	// Try to acquire read locks with timeout to detect deadlocks
	lockAcquired := make(chan struct{})
	go func() {
		pt.processesThreadsMtx.RLock()
		_ = len(pt.processesThreads) // Read data to avoid empty critical section
		pt.processesThreadsMtx.RUnlock()
		pt.processesChildrenMtx.RLock()
		_ = len(pt.processesChildren) // Read data to avoid empty critical section
		pt.processesChildrenMtx.RUnlock()
		close(lockAcquired)
	}()

	select {
	case <-lockAcquired:
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
func (pt *ProcessTree) GetProcess(entityId uint64) (*datastores.ProcessInfo, error) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	hash := uint32(entityId)
	proc, ok := pt.GetProcessByHash(hash)
	if !ok {
		return nil, datastores.ErrNotFound
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
	}, nil
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
		if childInfo, err := pt.GetProcess(uint64(childHash)); err == nil {
			children = append(children, childInfo)
		}
	}

	return children, nil
}

// GetAncestry retrieves the process ancestry chain up to maxDepth levels
// Returns slice of ProcessInfo with [0] = process itself, [1] = parent, [2] = grandparent, etc.
// If a parent is not found in the tree, the chain stops there
func (pt *ProcessTree) GetAncestry(entityId uint64, maxDepth int) ([]*datastores.ProcessInfo, error) {
	pt.lastAccessNano.Store(time.Now().UnixNano())

	if maxDepth <= 0 {
		return []*datastores.ProcessInfo{}, nil
	}

	ancestry := make([]*datastores.ProcessInfo, 0, maxDepth)
	currentHash := uint32(entityId)

	// Walk up the parent chain
	for i := 0; i < maxDepth; i++ {
		proc, ok := pt.GetProcessByHash(currentHash)
		if !ok {
			break // Process not in tree, stop here
		}

		info := proc.GetInfo()
		executable := proc.GetExecutable()

		ancestry = append(ancestry, &datastores.ProcessInfo{
			EntityID:  uint64(currentHash),
			PID:       uint32(info.GetPid()),
			PPID:      uint32(info.GetPPid()),
			Name:      info.GetName(),
			Exe:       executable.GetPath(),
			StartTime: info.GetStartTime(),
			UID:       info.GetUid(),
			GID:       info.GetGid(),
		})

		// Move to parent
		parentHash := proc.GetParentHash()
		if parentHash == 0 || parentHash == currentHash {
			break // No parent or circular reference
		}
		currentHash = parentHash
	}

	return ancestry, nil
}
