package detectors

import (
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

var (
	allDetectors []detection.EventDetector
	mu           sync.RWMutex
)

// register adds a detector to the global registry during package initialization.
// This is called by detector init() functions for automatic registration.
// Thread-safe: Mutex protects concurrent access during initialization.
func register(d detection.EventDetector) {
	mu.Lock()
	defer mu.Unlock()
	allDetectors = append(allDetectors, d)
}

// GetAllDetectors returns all detectors that registered via init().
// Returns a copy to prevent external modification of the registry.
// Thread-safe: Read lock allows concurrent access.
func GetAllDetectors() []detection.EventDetector {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]detection.EventDetector, len(allDetectors))
	copy(result, allDetectors)
	return result
}
