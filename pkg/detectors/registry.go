package detectors

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/version"
)

// parseHashMode converts a string hash mode to digest.CalcHashesOption
func parseHashMode(mode string) digest.CalcHashesOption {
	switch mode {
	case "inode":
		return digest.CalcHashesInode
	case "dev-inode":
		return digest.CalcHashesDevInode
	case "digest-inode":
		return digest.CalcHashesDigestInode
	default:
		return digest.CalcHashesNone
	}
}

// EnrichmentOptions represents available enrichment capabilities in Tracee.
// Used by the detector engine to validate enrichment requirements during registration.
type EnrichmentOptions struct {
	ExecEnv      bool                    // Whether exec environment variables are captured
	ExecHashMode digest.CalcHashesOption // Executable hash calculation mode
	Container    bool                    // Whether container enrichment is enabled (populates Event.Workload.Container fields and container datastore)
}

// entry holds detector metadata for dispatch
type entry struct {
	detector     detection.EventDetector
	definition   *detection.DetectorDefinition // Cached at registration (GetDefinition() result)
	eventID      v1beta1.EventId
	eventName    string
	enabled      bool                                     // Runtime state for enable/disable
	params       detection.DetectorParams                 // Stored for re-initialization on enable
	scopeFilters map[v1beta1.EventId]*filters.ScopeFilter // Scope filters per subscribed event
	dataFilters  map[v1beta1.EventId]*filters.DataFilter  // Data filters per subscribed event
}

// registry manages all registered detectors
type registry struct {
	mu                sync.RWMutex
	detectors         map[string]*entry // Detector ID -> entry
	eventNameIndex    map[string]string // Event name -> Detector ID (for collision detection)
	policyManager     *policy.Manager   // For policy checking during registration
	enrichmentOptions *EnrichmentOptions
}

// newRegistry creates a new detector registry
func newRegistry(policyManager *policy.Manager, enrichmentOptions *EnrichmentOptions) *registry {
	return &registry{
		detectors:         make(map[string]*entry),
		eventNameIndex:    make(map[string]string),
		policyManager:     policyManager,
		enrichmentOptions: enrichmentOptions,
	}
}

// isArchitectureSupported checks if the detector supports the current system architecture
// Empty requirements.Architectures means all architectures are supported
func isArchitectureSupported(requirements detection.DetectorRequirements, systemArch string) bool {
	if len(requirements.Architectures) == 0 {
		return true // No restriction = all architectures supported
	}

	for _, arch := range requirements.Architectures {
		if arch == systemArch {
			return true
		}
	}

	return false
}

// isTraceeVersionCompatible checks if the detector supports the current Tracee version
// Empty version constraints means all versions are supported
// MinTraceeVersion is inclusive, MaxTraceeVersion is exclusive
func isTraceeVersionCompatible(requirements detection.DetectorRequirements, currentVersion string) (bool, error) {
	// No constraints = all versions supported
	if requirements.MinTraceeVersion == nil && requirements.MaxTraceeVersion == nil {
		return true, nil
	}

	// Parse current Tracee version string to v1beta1.Version
	current, err := parseTraceeVersion(currentVersion)
	if err != nil {
		// If we can't parse version (e.g., dev build), allow detector
		return true, nil
	}

	// Check minimum version (inclusive)
	if requirements.MinTraceeVersion != nil {
		if compareVersions(current, requirements.MinTraceeVersion) < 0 {
			return false, nil
		}
	}

	// Check maximum version (exclusive)
	if requirements.MaxTraceeVersion != nil {
		if compareVersions(current, requirements.MaxTraceeVersion) >= 0 {
			return false, nil
		}
	}

	return true, nil
}

// compareVersions returns -1 if a < b, 0 if a == b, 1 if a > b
func compareVersions(a, b *v1beta1.Version) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// compareEventVersions compares events.Version with v1beta1.Version
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func compareEventVersions(a events.Version, b *v1beta1.Version) int {
	if a.Major() != b.Major {
		if a.Major() < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor() != b.Minor {
		if a.Minor() < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch() != b.Patch {
		if a.Patch() < b.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// isEventVersionCompatible checks if an event version satisfies the requirements
// Returns (compatible, error)
func isEventVersionCompatible(eventVersion events.Version, req detection.EventRequirement) (bool, error) {
	// Check minimum version (inclusive)
	if req.MinVersion != nil {
		if compareEventVersions(eventVersion, req.MinVersion) < 0 {
			return false, nil
		}
	}

	// Check maximum version (exclusive)
	if req.MaxVersion != nil {
		if compareEventVersions(eventVersion, req.MaxVersion) >= 0 {
			return false, nil
		}
	}

	return true, nil
}

// parseTraceeVersion parses Tracee version string to v1beta1.Version
// Handles formats like "v0.20.0", "0.20.0", "0.20.0-dev"
func parseTraceeVersion(versionStr string) (*v1beta1.Version, error) {
	// Remove leading 'v' if present
	versionStr = strings.TrimPrefix(versionStr, "v")

	// Split on '-' to remove suffixes like "-dev"
	parts := strings.Split(versionStr, "-")
	versionParts := strings.Split(parts[0], ".")

	if len(versionParts) < 3 {
		return nil, fmt.Errorf("invalid version format: %s", versionStr)
	}

	major, err := strconv.ParseUint(versionParts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %w", err)
	}

	minor, err := strconv.ParseUint(versionParts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %w", err)
	}

	patch, err := strconv.ParseUint(versionParts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid patch version: %w", err)
	}

	return &v1beta1.Version{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
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

	// Validate enrichment requirements
	for _, enrichReq := range definition.Requirements.Enrichments {
		available := false
		modeMismatch := false
		var actualMode string

		switch enrichReq.Name {
		case detection.EnrichmentExecEnv:
			available = r.enrichmentOptions != nil && r.enrichmentOptions.ExecEnv
		case detection.EnrichmentExecHash:
			available = r.enrichmentOptions != nil && r.enrichmentOptions.ExecHashMode != digest.CalcHashesNone
			// If specific config requested, mode must match
			if available && enrichReq.Config != "" {
				// Parse requested mode string to enum
				requestedMode := parseHashMode(enrichReq.Config)
				if requestedMode == digest.CalcHashesNone {
					return fmt.Errorf("detector %s requires invalid exec-hash mode: %s", detectorID, enrichReq.Config)
				}
				actualMode = r.enrichmentOptions.ExecHashMode.String()
				if requestedMode != r.enrichmentOptions.ExecHashMode {
					available = false
					modeMismatch = true
				}
			}
		case detection.EnrichmentContainer:
			available = r.enrichmentOptions != nil && r.enrichmentOptions.Container
		default:
			return fmt.Errorf("detector %s requires unknown enrichment: %s", detectorID, enrichReq.Name)
		}

		if !available && enrichReq.Dependency == detection.DependencyRequired {
			// Provide specific error message for mode mismatch
			if modeMismatch {
				return fmt.Errorf("detector %s requires enrichment %q with mode %q, but current mode is %q",
					detectorID, enrichReq.Name, enrichReq.Config, actualMode)
			}
			return fmt.Errorf("detector %s requires enrichment %q which is not enabled", detectorID, enrichReq.Name)
		}

		if !available && enrichReq.Dependency == detection.DependencyOptional {
			// Provide specific warning for mode mismatch
			if modeMismatch {
				logger.Warnw("Detector enrichment mode mismatch",
					"detector", detectorID,
					"enrichment", enrichReq.Name,
					"requested_mode", enrichReq.Config,
					"actual_mode", actualMode,
					"dependency", "optional")
			} else {
				logger.Warnw("Detector enrichment not available",
					"detector", detectorID,
					"enrichment", enrichReq.Name,
					"dependency", "optional")
			}
		}
	}

	// Check architecture compatibility using runtime.GOARCH
	if !isArchitectureSupported(definition.Requirements, runtime.GOARCH) {
		logger.Debugw("Skipping detector - architecture not supported",
			"detector", detectorID,
			"required", definition.Requirements.Architectures,
			"current", runtime.GOARCH)
		return nil // Skip registration, not an error
	}

	// Check Tracee version compatibility
	compatible, err := isTraceeVersionCompatible(definition.Requirements, version.GetVersion())
	if err != nil {
		logger.Debugw("Failed to parse Tracee version for detector compatibility check",
			"detector", detectorID,
			"error", err)
		// Continue registration on parse error (e.g., dev builds)
	}
	if !compatible {
		logger.Debugw("Skipping detector - Tracee version not compatible",
			"detector", detectorID,
			"min_version", definition.Requirements.MinTraceeVersion,
			"max_version", definition.Requirements.MaxTraceeVersion,
			"current", version.GetVersion())
		return nil // Skip registration, not an error
	}

	// Lookup pre-allocated event ID from events.Core
	eventID, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return fmt.Errorf("detector %s: event '%s' was not pre-registered in events.Core", detectorID, eventName)
	}
	r.eventNameIndex[eventName] = detectorID

	// Check if detector's output event is selected by policy
	enabled := r.policyManager != nil && r.policyManager.IsEventSelected(eventID)

	// Parse scope and data filters for all event requirements
	// Use maps for O(1) lookup and to handle multiple requirements for same event
	scopeFilters := make(map[v1beta1.EventId]*filters.ScopeFilter)
	dataFilters := make(map[v1beta1.EventId]*filters.DataFilter)

	for _, req := range definition.Requirements.Events {
		// Lookup event ID by name
		var reqEventID v1beta1.EventId
		var eventName string
		var eventVersion events.Version
		var hasVersion bool

		if predefinedID := events.LookupPredefinedEventID(req.Name); predefinedID != 0 {
			reqEventID = v1beta1.EventId(predefinedID)
			eventDef := events.Core.GetDefinitionByID(predefinedID)
			eventName = eventDef.GetName()
			eventVersion = eventDef.GetVersion()
			hasVersion = true
		} else {
			// Check if it's a detector-produced event
			if producerID, exists := r.eventNameIndex[req.Name]; exists {
				if producerEntry, ok := r.detectors[producerID]; ok {
					reqEventID = producerEntry.eventID
					eventName = producerEntry.definition.ProducedEvent.Name
					// Get version from the producer detector's ProducedEvent definition
					if producerEntry.definition.ProducedEvent.Version != nil {
						eventVersion = events.NewVersion(
							producerEntry.definition.ProducedEvent.Version.Major,
							producerEntry.definition.ProducedEvent.Version.Minor,
							producerEntry.definition.ProducedEvent.Version.Patch,
						)
						hasVersion = true
					}
				}
			}
		}

		if reqEventID == 0 {
			// Event not found
			if req.Dependency == detection.DependencyRequired {
				return fmt.Errorf("detector %s: required event '%s' not found", detectorID, req.Name)
			}
			logger.Debugw("Optional event not found for detector",
				"detector", detectorID,
				"event", req.Name)
			continue
		}

		// Check event version compatibility (unified for both predefined and detector events)
		if hasVersion && (req.MinVersion != nil || req.MaxVersion != nil) {
			compatible, err := isEventVersionCompatible(eventVersion, req)
			if err != nil {
				return fmt.Errorf("detector %s, event %s: version validation error: %w",
					detectorID, eventName, err)
			}
			if !compatible {
				if req.Dependency == detection.DependencyRequired {
					return fmt.Errorf("detector %s: required event '%s' version incompatible (available: %s, required: min=%v max=%v)",
						detectorID, eventName, eventVersion,
						req.MinVersion, req.MaxVersion)
				}
				logger.Debugw("Skipping optional event - version incompatible",
					"detector", detectorID,
					"event", eventName,
					"available_version", eventVersion,
					"required_min", req.MinVersion,
					"required_max", req.MaxVersion)
				continue
			}
		}

		// Parse scope filters
		if len(req.ScopeFilters) > 0 {
			// Get or create scope filter for this event ID
			scopeFilter, exists := scopeFilters[reqEventID]
			if !exists {
				scopeFilter = filters.NewScopeFilter()
				scopeFilters[reqEventID] = scopeFilter
			}

			// Parse and add scope filters for this requirement
			for _, filterStr := range req.ScopeFilters {
				field, operatorAndValues := parseFilterString(filterStr)
				if err := scopeFilter.Parse(field, operatorAndValues); err != nil {
					return fmt.Errorf("detector %s, event %s: invalid scope filter '%s': %w",
						detectorID, req.Name, filterStr, err)
				}
			}
		}

		// Parse data filters
		if len(req.DataFilters) > 0 {
			// Get or create data filter for this event ID
			dataFilter, exists := dataFilters[reqEventID]
			if !exists {
				dataFilter = filters.NewDetectorDataFilter() // Use detector-specific filter
				dataFilters[reqEventID] = dataFilter
			}

			// Parse and add data filters for this requirement
			for _, filterStr := range req.DataFilters {
				fieldName, operatorAndValues := parseFilterString(filterStr)
				if err := dataFilter.Parse(events.ID(reqEventID), fieldName, operatorAndValues); err != nil {
					return fmt.Errorf("detector %s, event %s: invalid data filter '%s': %w",
						detectorID, req.Name, filterStr, err)
				}
			}
		}
	}

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
		detector:     detector,
		definition:   &definition,
		eventID:      v1beta1.EventId(eventID),
		eventName:    eventName,
		enabled:      enabled, // enabled = initialized
		params:       params,  // Store for potential re-initialization
		scopeFilters: scopeFilters,
		dataFilters:  dataFilters,
	}

	// Store detector entry (registered regardless of selection for future runtime changes)
	r.detectors[detectorID] = detectorEntry

	logger.Debugw("Registered detector",
		"detector", detectorID,
		"event", eventName)

	return nil
}

// GetDetectorCount returns the number of registered detectors
func (r *registry) GetDetectorCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.detectors)
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

		// Validate scope filter syntax
		if _, err := parseScopeFilters(req.ScopeFilters, fmt.Sprintf("event %s", req.Name)); err != nil {
			return err
		}

		// Validate data filter syntax
		// We validate syntax only here, not field names (which require event ID)
		for _, dataFilterStr := range req.DataFilters {
			fieldName, operatorAndValues := parseFilterString(dataFilterStr)
			if fieldName == "" || operatorAndValues == "" {
				return fmt.Errorf("event %s: invalid data filter '%s' (missing field or operator)", req.Name, dataFilterStr)
			}
		}
	}

	return nil
}

// parseScopeFilters parses a list of scope filter strings into a ScopeFilter
// Returns nil if filterStrings is empty
// Returns error if any filter string is invalid
func parseScopeFilters(filterStrings []string, contextMsg string) (*filters.ScopeFilter, error) {
	if len(filterStrings) == 0 {
		return nil, nil
	}

	scopeFilter := filters.NewScopeFilter()
	for _, filterStr := range filterStrings {
		field, operatorAndValues := parseFilterString(filterStr)
		if err := scopeFilter.Parse(field, operatorAndValues); err != nil {
			return nil, fmt.Errorf("%s: invalid scope filter '%s': %w", contextMsg, filterStr, err)
		}
	}
	return scopeFilter, nil
}

// parseFilterString splits a filter string into field and operatorAndValues
// Examples: "container" -> ("container", ""), "pathname=/tmp/*" -> ("pathname", "=/tmp/*")
func parseFilterString(filterStr string) (field string, operatorAndValues string) {
	operators := []string{"!=", "<=", ">=", "=", "<", ">"}
	for _, op := range operators {
		if idx := strings.Index(filterStr, op); idx != -1 {
			return filterStr[:idx], filterStr[idx:]
		}
	}
	// No operator found, return whole string as field (valid for scope filters)
	return filterStr, ""
}
