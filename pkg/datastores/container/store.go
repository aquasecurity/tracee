package container

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (m *Manager) Name() string {
	return "container"
}

// GetHealth returns the current health status of the datastore
func (m *Manager) GetHealth() *datastores.HealthInfo {
	// Try to acquire read lock with timeout to detect deadlocks
	lockAcquired := make(chan struct{})
	go func() {
		m.lock.RLock()
		_ = len(m.containerMap) // Read data to avoid empty critical section
		m.lock.RUnlock()
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
func (m *Manager) GetMetrics() *datastores.DataStoreMetrics {
	m.lock.RLock()
	itemCount := int64(len(m.containerMap))
	m.lock.RUnlock()

	lastAccessNano := m.lastAccessNano.Load()

	return &datastores.DataStoreMetrics{
		ItemCount:    itemCount,
		SuccessCount: 0, // TODO: Track in Phase 2
		ErrorCount:   0, // TODO: Track in Phase 2
		CacheHits:    0, // TODO: Track in Phase 2
		CacheMisses:  0, // TODO: Track in Phase 2
		LastAccess:   time.Unix(0, lastAccessNano),
	}
}

// ContainerStore interface implementation

// GetContainer retrieves container information by container ID
func (m *Manager) GetContainer(id string) (*datastores.ContainerInfo, bool) {
	m.lastAccessNano.Store(time.Now().UnixNano())

	m.lock.RLock()
	cont, ok := m.containerMap[id]
	m.lock.RUnlock()

	if !ok {
		return nil, false
	}

	return convertContainer(&cont), true
}

// GetContainerByName retrieves container information by container name
func (m *Manager) GetContainerByName(name string) (*datastores.ContainerInfo, bool) {
	m.lastAccessNano.Store(time.Now().UnixNano())

	m.lock.RLock()
	// Linear search through containers for name match
	// TODO Phase 2: Add name→ID index for O(1) lookup
	var foundCont *Container
	for _, cont := range m.containerMap {
		if cont.Name == name {
			contCopy := cont
			foundCont = &contCopy
			break
		}
	}
	m.lock.RUnlock()

	if foundCont == nil {
		return nil, false
	}

	return convertContainer(foundCont), true
}

// convertContainer converts internal Container to public ContainerInfo
func convertContainer(cont *Container) *datastores.ContainerInfo {
	var podInfo *datastores.K8sPodInfo
	if cont.Pod.Name != "" || cont.Pod.UID != "" {
		podInfo = &datastores.K8sPodInfo{
			Name:      cont.Pod.Name,
			UID:       cont.Pod.UID,
			Namespace: cont.Pod.Namespace,
			Sandbox:   cont.Pod.Sandbox,
		}
	}

	return &datastores.ContainerInfo{
		ID:          cont.ContainerId,
		Name:        cont.Name,
		Image:       cont.Image,
		ImageDigest: cont.ImageDigest,
		Runtime:     cont.Runtime.String(),
		StartTime:   cont.CreatedAt,
		Pod:         podInfo,
	}
}
