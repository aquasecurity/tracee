package system

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// Store implements the SystemStore interface with immutable system information
type Store struct {
	info *datastores.SystemInfo
}

// New creates a new SystemStore with the provided system information
func New(info *datastores.SystemInfo) datastores.SystemStore {
	return &Store{
		info: info,
	}
}

// Name returns the datastore name
func (s *Store) Name() string {
	return datastores.System
}

// GetHealth returns the health status of the datastore
// SystemStore is always healthy since it contains immutable data
func (s *Store) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthHealthy,
		Message:   "",
		LastCheck: time.Now(),
	}
}

// GetMetrics returns operational metrics for the datastore
// SystemStore has zero metrics since it's read-only immutable data
func (s *Store) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:    1, // Always contains exactly one SystemInfo
		SuccessCount: 0,
		ErrorCount:   0,
		CacheHits:    0,
		CacheMisses:  0,
		LastAccess:   time.Time{},
	}
}

// GetSystemInfo returns the complete system information
func (s *Store) GetSystemInfo() *datastores.SystemInfo {
	return s.info
}
