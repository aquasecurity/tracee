package detectors

import (
	"errors"
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// entry holds detector metadata for dispatch
type entry struct {
	detector   detection.EventDetector
	definition *detection.DetectorDefinition // Cached at registration (GetDefinition() result)
	eventID    v1beta1.EventId
	eventName  string
	enabled    bool                     // Runtime state for enable/disable
	params     detection.DetectorParams // Stored for re-initialization on enable
}

// registry manages all registered detectors
type registry struct {
	mu             sync.RWMutex
	detectors      map[string]*entry // Detector ID -> entry
	eventNameIndex map[string]string // Event name -> Detector ID (for collision detection)
	policyManager  *policy.Manager   // For policy checking during registration
}

// newRegistry creates a new detector registry
func newRegistry(policyManager *policy.Manager) *registry {
	return &registry{
		detectors:      make(map[string]*entry),
		eventNameIndex: make(map[string]string),
		policyManager:  policyManager,
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

	// Validate datastore requirements (check all required datastores are available)
	for _, dsReq := range definition.Requirements.DataStores {
		if !params.DataStores.IsAvailable(dsReq.Name) {
			// Only fail registration if the datastore is required
			if dsReq.Dependency == detection.DependencyRequired {
				return fmt.Errorf("detector %s requires datastore %q but it is not available", detectorID, dsReq.Name)
			}
			// Log warning for optional datastores
			logger.Debugw("Optional datastore not available for detector",
				"detector", detectorID,
				"datastore", dsReq.Name)
		}
	}

	// Lookup pre-allocated event ID from events.Core
	eventID, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return fmt.Errorf("detector %s: event '%s' was not pre-registered in events.Core", detectorID, eventName)
	}
	r.eventNameIndex[eventName] = detectorID

	// Check if detector's output event is selected by policy
	enabled := r.policyManager != nil && r.policyManager.IsEventSelected(eventID)

	// Only initialize if selected to avoid resource waste
	if enabled {
		// Initialize detector before adding to registry
		if err := detector.Init(params); err != nil {
			return fmt.Errorf("failed to initialize detector %s: %w", detectorID, err)
		}
	} else {
		logger.Debugw("Skipping detector initialization (not selected by policy)",
			"detector", detectorID,
			"event", eventName)
	}

	// Create detector entry after initialization check
	detectorEntry := &entry{
		detector:   detector,
		definition: &definition,
		eventID:    v1beta1.EventId(eventID),
		eventName:  eventName,
		enabled:    enabled, // enabled = initialized
		params:     params,  // Store for potential re-initialization
	}

	// Store detector entry (registered regardless of selection for future runtime changes)
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

	// Clean up detector resources if enabled (initialized) and implements Close()
	if detector.enabled {
		if closer, ok := detector.detector.(detection.DetectorCloser); ok {
			if err := closer.Close(); err != nil {
				return fmt.Errorf("failed to close detector %s: %w", detectorID, err)
			}
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
// Calls Init() if detector was never initialized or was previously disabled
func (r *registry) EnableDetector(detectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	detector, exists := r.detectors[detectorID]
	if !exists {
		return fmt.Errorf("detector %s not registered", detectorID)
	}

	// Already enabled
	if detector.enabled {
		return nil
	}

	// Initialize detector
	if err := detector.detector.Init(detector.params); err != nil {
		return fmt.Errorf("failed to initialize detector %s: %w", detectorID, err)
	}

	detector.enabled = true
	logger.Debugw("Detector enabled",
		"detector", detectorID,
		"event", detector.eventName)

	return nil
}

// DisableDetector disables a registered detector (runtime operation)
// Calls Close() to release resources if detector implements DetectorCloser
func (r *registry) DisableDetector(detectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	detector, exists := r.detectors[detectorID]
	if !exists {
		return fmt.Errorf("detector %s not registered", detectorID)
	}

	// Already disabled
	if !detector.enabled {
		return nil
	}

	// Call Close() if detector implements it
	if closer, ok := detector.detector.(detection.DetectorCloser); ok {
		if err := closer.Close(); err != nil {
			return fmt.Errorf("failed to close detector %s: %w", detectorID, err)
		}
	}

	detector.enabled = false
	logger.Debugw("Detector disabled",
		"detector", detectorID,
		"event", detector.eventName)

	return nil
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
