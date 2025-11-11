package detectors

import (
	"fmt"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	builtin "github.com/aquasecurity/tracee/detectors"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// CollectAllDetectors gathers all detectors from built-in sources and YAML directories.
// This is the canonical detector collection function used for both event registration
// and detector initialization. Extensions should modify this function to inject additional detectors.
func CollectAllDetectors(yamlSearchDirs []string) []detection.EventDetector {
	var allDetectors []detection.EventDetector

	// Collect from built-in detectors module (auto-registered via init())
	allDetectors = append(allDetectors, builtin.GetAllDetectors()...)

	// Load YAML detectors from search directories
	var yamlDirs []string
	if len(yamlSearchDirs) > 0 {
		yamlDirs = yamlSearchDirs
	} else {
		// Use default search paths if none specified
		yamlDirs = yamldetectors.GetDefaultSearchPaths()
	}

	yamlDets, errors := yamldetectors.LoadFromDirectories(yamlDirs)
	if len(errors) > 0 {
		for _, err := range errors {
			logger.Warnw("Failed to load YAML detector", "error", err)
		}
	}

	if len(yamlDets) > 0 {
		logger.Debugw("Loaded YAML detectors", "count", len(yamlDets), "directories", yamlDirs)
		allDetectors = append(allDetectors, yamlDets...)
	}

	logger.Debugw("Collected detectors", "total", len(allDetectors), "yaml", len(yamlDets))

	return allDetectors
}

// CreateEventsFromDetectors pre-registers detector events in events.Core before policy initialization.
// This allows the policy manager to select detector events just like regular events.
// Returns mapping of event name -> allocated event ID.
func CreateEventsFromDetectors(startID events.ID, detectors []detection.EventDetector) (map[string]events.ID, error) {
	eventNameToID := make(map[string]events.ID)
	nextDynamicID := startID

	for _, detector := range detectors {
		def := detector.GetDefinition()
		eventName := def.ProducedEvent.Name

		// Check if event has predefined ID
		var eventID events.ID
		if predefinedID, exists := events.PredefinedDetectorEvents[eventName]; exists {
			// Validate predefined ID doesn't already have a schema (collision check)
			if events.Core.IsDefined(predefinedID) {
				return nil, fmt.Errorf("predefined ID %d for event '%s' already has schema - collision with built-in event", predefinedID, eventName)
			}
			eventID = predefinedID
		} else {
			// Allocate dynamic ID
			eventID = nextDynamicID
			nextDynamicID++
		}

		// Enforce event name uniqueness across all detectors
		// Required for unambiguous dependency resolution and consistent event schema
		// When detector B depends on event "foo", it must resolve to exactly one definition
		if existingID, exists := eventNameToID[eventName]; exists {
			return nil, fmt.Errorf("duplicate event name '%s' (IDs %d and %d)", eventName, existingID, eventID)
		}

		// Convert detector requirements to event dependencies
		dependencies := convertRequirementsToDependencies(def.Requirements.Events, eventNameToID)

		// Build event definition with detector's schema
		eventDef := events.NewDefinition(
			eventID,                // id
			events.Sys32Undefined,  // id32Bit
			def.ProducedEvent.Name, // name
			convertVersion(def.ProducedEvent.Version), // version
			def.ProducedEvent.Description,             // description
			false,                                     // internal
			false,                                     // syscall
			[]string{"detectors", "default"},          // sets
			events.NewDependencyStrategy(dependencies),          // deps
			convertFieldsToDataFields(def.ProducedEvent.Fields), // fields
			map[string]interface{}{"detectorID": def.ID},        // properties
		)

		// Add to events.Core
		if err := events.Core.Add(eventID, eventDef); err != nil {
			return nil, fmt.Errorf("failed to add event '%s': %w", eventName, err)
		}

		eventNameToID[eventName] = eventID
	}

	return eventNameToID, nil
}

// convertRequirementsToDependencies converts detector EventRequirements to event dependencies
// Only DependencyRequired events are added - optional dependencies are handled separately
func convertRequirementsToDependencies(reqs []detection.EventRequirement, eventNameToID map[string]events.ID) events.Dependencies {
	depIDs := []events.ID{}

	for _, req := range reqs {
		// Skip optional dependencies - they shouldn't be in event dependencies
		if req.Dependency != detection.DependencyRequired {
			continue
		}

		// Lookup in core events first
		if id, found := events.Core.GetDefinitionIDByName(req.Name); found {
			depIDs = append(depIDs, id)
			continue
		}

		// Check if it's another detector event we've already registered
		if id, found := eventNameToID[req.Name]; found {
			depIDs = append(depIDs, id)
			continue
		}

		// Not found yet - might be registered later in the loop (detectors processed in arbitrary order)
		// Don't log error - dependency manager will validate after all detectors are processed
	}

	return events.NewDependencies(depIDs, []events.KSymbol{}, []events.Probe{}, []events.TailCall{}, events.Capabilities{})
}

// convertVersion converts protobuf Version to events.Version
// Defaults to 1.0.0 if version is nil
func convertVersion(v *v1beta1.Version) events.Version {
	if v == nil {
		return events.NewVersion(1, 0, 0)
	}
	return events.NewVersion(
		v.Major,
		v.Minor,
		v.Patch,
	)
}

// convertFieldsToDataFields converts protobuf EventField to events.DataField
// Maps field names and types from detector schema to Tracee's internal event schema
func convertFieldsToDataFields(fields []*v1beta1.EventField) []events.DataField {
	if len(fields) == 0 {
		return []events.DataField{}
	}

	dataFields := make([]events.DataField, 0, len(fields))
	for _, field := range fields {
		dataFields = append(dataFields, events.DataField{
			ArgMeta: trace.ArgMeta{
				Name: field.Name,
				Type: field.Type,
			},
			// DecodeAs left as default (zero value) - detectors define raw types
		})
	}

	return dataFields
}
