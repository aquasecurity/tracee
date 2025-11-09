package container

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (m *Manager) Name() string {
	return datastores.Container
}

// GetHealth returns the current health status of the datastore
func (m *Manager) GetHealth() *datastores.HealthInfo {
	// Try to acquire lock with retries to distinguish between busy (healthy) and deadlocked (unhealthy)
	const maxAttempts = 10
	const retryDelay = 10 * time.Millisecond // Total max wait: 100ms

	for attempt := range maxAttempts {
		if !m.lock.TryRLock() {
			// Failed to acquire lock, retry if not last attempt
			if attempt < maxAttempts-1 {
				time.Sleep(retryDelay)
			}
			continue
		}

		// Verify internal state is healthy
		if m.containerMap == nil {
			m.lock.RUnlock()
			return &datastores.HealthInfo{
				Status:    datastores.HealthUnhealthy,
				Message:   "container map not initialized",
				LastCheck: time.Now(),
			}
		}

		m.lock.RUnlock()
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
func (m *Manager) GetContainer(id string) (*datastores.ContainerInfo, error) {
	m.lastAccessNano.Store(time.Now().UnixNano())

	m.lock.RLock()
	cont, ok := m.containerMap[id]
	m.lock.RUnlock()

	if !ok {
		return nil, datastores.ErrNotFound
	}

	return convertContainer(&cont), nil
}

// GetContainerByName retrieves container information by container name
func (m *Manager) GetContainerByName(name string) (*datastores.ContainerInfo, error) {
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
		return nil, datastores.ErrNotFound
	}

	return convertContainer(foundCont), nil
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
