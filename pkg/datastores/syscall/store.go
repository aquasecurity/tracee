package syscall

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/events"
)

// Store implements the SyscallStore interface by wrapping events.DefinitionGroup
// It provides access to syscall metadata for the current architecture
type Store struct {
	eventCore *events.DefinitionGroup
}

// New creates a new SyscallStore with the provided event definitions
func New(eventCore *events.DefinitionGroup) datastores.SyscallStore {
	return &Store{
		eventCore: eventCore,
	}
}

// Name returns the datastore name
func (s *Store) Name() string {
	return datastores.Syscall
}

// GetHealth returns the health status of the datastore
// SyscallStore is always healthy since it wraps immutable event definitions
func (s *Store) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthHealthy,
		Message:   "syscall store operational",
		LastCheck: time.Now(),
	}
}

// GetMetrics returns operational metrics for the datastore
func (s *Store) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{
		ItemCount:    0, // Not tracked for syscall store
		SuccessCount: 0,
		ErrorCount:   0,
		CacheHits:    0,
		CacheMisses:  0,
		LastAccess:   time.Now(),
	}
}

// GetSyscallName returns the syscall name for a given ID
// Returns empty string and false if the syscall ID is not found or is not a syscall
func (s *Store) GetSyscallName(id int32) (string, bool) {
	def := s.eventCore.GetDefinitionByID(events.ID(id))

	// Check if definition was found (Undefined means not found)
	if def.GetID() == events.Undefined {
		return "", false
	}

	// Only return name if this is actually a syscall
	if !def.IsSyscall() {
		return "", false
	}

	return def.GetName(), true
}

// GetSyscallID returns the syscall ID for a given name
// Returns 0 and false if the syscall name is not found or is not a syscall
func (s *Store) GetSyscallID(name string) (int32, bool) {
	id, found := s.eventCore.GetDefinitionIDByName(name)
	if !found {
		return 0, false
	}

	// Verify this is actually a syscall
	def := s.eventCore.GetDefinitionByID(id)
	if def.GetID() == events.Undefined || !def.IsSyscall() {
		return 0, false
	}

	return int32(id), true
}
