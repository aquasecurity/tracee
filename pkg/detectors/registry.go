package detectors

import (
	"errors"
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/events"
)

// entry holds detector metadata for dispatch
type entry struct {
	detector   detection.EventDetector
	definition *detection.DetectorDefinition // Cached at registration (GetDefinition() result)
	eventID    v1beta1.EventId
	eventName  string
	enabled    bool // Runtime state for enable/disable
}

// registry manages all registered detectors
type registry struct {
	mu             sync.RWMutex
	detectors      map[string]*entry // Detector ID -> entry
	eventNameIndex map[string]string // Event name -> Detector ID (for collision detection)
	nextDynamicID  v1beta1.EventId   // Next dynamic event ID to allocate (starts at 7000)
}

// newRegistry creates a new detector registry
func newRegistry() *registry {
	return &registry{
		detectors:      make(map[string]*entry),
		eventNameIndex: make(map[string]string),
		nextDynamicID:  v1beta1.EventId(events.StartDetectorID), // Dynamic detector IDs start at 7000
	}
}

// RegisterDetector adds a detector to the engine registry
// Can be called at startup or runtime for dynamic detector loading
// Engine allocates event ID, caches definition, and initializes detector atomically
// If any step fails, detector is not registered
func (r *registry) RegisterDetector(
	detector detection.EventDetector,
	params detection.DetectorParams,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Get and cache definition - GetDefinition() called only once at registration
	definition := detector.GetDefinition()
	detectorID := definition.ID
	eventName := definition.ProducedEvent.Name

	// Check for detector ID conflicts (one detector per detector ID)
	if _, exists := r.detectors[detectorID]; exists {
		return fmt.Errorf("detector ID %s already registered", detectorID)
	}

	// Validate event requirements (version constraints, filter syntax, etc.)
	if err := validateEventRequirements(definition.Requirements.Events); err != nil {
		return fmt.Errorf("detector %s has invalid requirements: %w", detectorID, err)
	}

	// Allocate event ID - enforces unique event names for all detectors
	eventID, err := r.allocateEventID(eventName, detectorID)
	if err != nil {
		return fmt.Errorf("detector %s: %w", detectorID, err)
	}

	// Initialize detector before adding to registry
	// If Init fails, detector is never registered (atomic operation)
	if err := detector.Init(params); err != nil {
		return fmt.Errorf("failed to initialize detector %s: %w", detectorID, err)
	}

	// Store detector entry with cached definition
	// Definition cached at registration to avoid repeated GetDefinition() calls
	// Detectors MUST ensure GetDefinition() is idempotent and returns constant data
	detectorEntry := &entry{
		detector:   detector,
		definition: &definition, // Cache definition
		eventID:    eventID,
		eventName:  eventName,
		enabled:    true, // Detectors start enabled by default
	}
	r.detectors[detectorID] = detectorEntry

	return nil
}

// UnregisterDetector removes a detector from the registry
// Can be called at startup or runtime for dynamic detector unloading
// This is a structural operation that removes the detector completely
func (r *registry) UnregisterDetector(detectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	detector, exists := r.detectors[detectorID]
	if !exists {
		return fmt.Errorf("detector %s not registered", detectorID)
	}

	// Clean up detector resources if it implements Close()
	if closer, ok := detector.detector.(detection.DetectorCloser); ok {
		if err := closer.Close(); err != nil {
			return fmt.Errorf("failed to close detector %s: %w", detectorID, err)
		}
	}

	// Clean up event name index
	delete(r.eventNameIndex, detector.eventName)
	delete(r.detectors, detectorID)
	// TODO: Clean up event dependencies if no other detectors depend on them

	return nil
}

// ListDetectors returns all registered detector IDs
func (r *registry) ListDetectors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	detectorIDs := make([]string, 0, len(r.detectors))
	for id := range r.detectors {
		detectorIDs = append(detectorIDs, id)
	}
	return detectorIDs
}

// GetDetector retrieves a detector by ID
func (r *registry) GetDetector(detectorID string) (detection.EventDetector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	detector, exists := r.detectors[detectorID]
	if !exists {
		return nil, fmt.Errorf("detector %s not registered", detectorID)
	}
	return detector.detector, nil
}

// EnableDetector enables a registered detector (runtime operation)
func (r *registry) EnableDetector(detectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	detector, exists := r.detectors[detectorID]
	if !exists {
		return fmt.Errorf("detector %s not registered", detectorID)
	}

	detector.enabled = true
	return nil
}

// DisableDetector disables a registered detector (runtime operation)
func (r *registry) DisableDetector(detectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	detector, exists := r.detectors[detectorID]
	if !exists {
		return fmt.Errorf("detector %s not registered", detectorID)
	}

	detector.enabled = false
	return nil
}

// allocateEventID is an engine-internal helper for event ID allocation
// Implements two-phase lookup: predefined events first, then dynamic allocation
// Enforces global uniqueness of event names across all detector types
//
// Why enforce uniqueness?
//  1. Event Identity: Each event name must map to exactly one event ID and schema
//  2. Detector Chains: Detectors can depend on events from other detectors (e.g., threat detector
//     consuming derived events). Unique event names ensure unambiguous dependency resolution and
//     correct dispatch routing through detector chains.
//  3. Consistency: Users expect one canonical source/definition per event name (e.g., in 'tracee list')
//  4. Security: Prevents event name spoofing and ensures engine control over event identity
func (r *registry) allocateEventID(
	eventName string,
	detectorID string,
) (v1beta1.EventId, error) {
	// Check if another detector already produces this event name
	if existingDetectorID, exists := r.eventNameIndex[eventName]; exists {
		return 0, fmt.Errorf("event name '%s' already produced by detector %s",
			eventName, existingDetectorID)
	}

	// Phase 1: Check if this is a predefined event (lookup in event definitions)
	if predefinedID := events.LookupPredefinedEventID(eventName); predefinedID != 0 {
		// Found in enum - use predefined ID (e.g., "hooked_syscall" → 2021)
		r.eventNameIndex[eventName] = detectorID
		return v1beta1.EventId(predefinedID), nil
	}

	// Phase 2: Allocate new dynamic ID (starting from 7000)
	newID := r.nextDynamicID
	r.nextDynamicID++
	r.eventNameIndex[eventName] = detectorID
	return newID, nil
}

// validateEventRequirements validates event requirements
// Checks dependency types, version constraints, and filter syntax
func validateEventRequirements(requirements []detection.EventRequirement) error {
	for _, req := range requirements {
		// Validate event name is not empty
		if req.Name == "" {
			return errors.New("event requirement has empty name")
		}

		// Validate version constraints if specified
		if req.MinVersion != nil && req.MaxVersion != nil {
			// Check that min < max
			minVer := req.MinVersion
			maxVer := req.MaxVersion
			if minVer.Major > maxVer.Major ||
				(minVer.Major == maxVer.Major && minVer.Minor > maxVer.Minor) ||
				(minVer.Major == maxVer.Major && minVer.Minor == maxVer.Minor && minVer.Patch >= maxVer.Patch) {
				return fmt.Errorf("event %s: MinVersion must be less than MaxVersion", req.Name)
			}
		}

		// TODO: Validate filter syntax using existing policy filter parsers
		// This would parse DataFilters and ScopeFilters to ensure they're valid
	}

	return nil
}
