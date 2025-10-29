package detectors

import (
	"context"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
)

// dispatcher manages event routing to detectors based on their requirements
type dispatcher struct {
	mu          sync.RWMutex
	dispatchMap map[v1beta1.EventId][]string // Event ID -> Detector IDs
}

// newDispatcher creates a new event dispatcher
func newDispatcher() *dispatcher {
	return &dispatcher{
		dispatchMap: make(map[v1beta1.EventId][]string),
	}
}

// rebuild reconstructs the dispatch mapping from registered detectors
// Called by the registry after Register/Unregister operations
func (d *dispatcher) rebuild(registry *registry) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clear existing map
	d.dispatchMap = make(map[v1beta1.EventId][]string)

	// Build mapping from detector requirements
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	for detectorID, detectorEntry := range registry.detectors {
		for _, req := range detectorEntry.definition.Requirements.Events {
			// Lookup event ID by name (check predefined events first)
			var eventID v1beta1.EventId
			if predefinedID := events.LookupPredefinedEventID(req.Name); predefinedID != 0 {
				eventID = v1beta1.EventId(predefinedID)
			} else {
				// If not predefined, check if it's a detector-produced event
				// Look up in event name index to see if another detector produces it
				if producerID, exists := registry.eventNameIndex[req.Name]; exists {
					if producerEntry, ok := registry.detectors[producerID]; ok {
						eventID = producerEntry.eventID
					}
				}
			}

			// Add detector to dispatch list for this event
			if eventID != 0 {
				d.dispatchMap[eventID] = append(d.dispatchMap[eventID], detectorID)
			}
		}
	}
}

// dispatchToDetectors dispatches an event to all registered detectors that are interested in it
// Returns the output events produced by detectors
func (d *dispatcher) dispatchToDetectors(ctx context.Context, inputEvent *v1beta1.Event, registry *registry) ([]*v1beta1.Event, error) {
	var outputEvents []*v1beta1.Event

	// Stage 1: Event ID → Detector IDs (dispatch mapping)
	d.mu.RLock()
	detectorIDs := d.dispatchMap[inputEvent.Id]
	d.mu.RUnlock()

	// Stage 2: For each detector ID, get detector entry and process
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	for _, detectorID := range detectorIDs {
		detector := registry.detectors[detectorID]
		if detector == nil {
			continue // Should never happen, but be defensive
		}

		// Skip disabled detectors
		if !detector.enabled {
			continue
		}

		// TODO: Apply data and scope filters before calling OnEvent()
		// Filtering ensures only matching events reach OnEvent() based on detector requirements

		// Call detector with event
		detectorOutputs, err := detector.detector.OnEvent(ctx, inputEvent)
		if err != nil {
			// Log error but continue processing other detectors
			// Errors are never fatal - detectors must be resilient
			// TODO: Add logging and metrics when available
			continue
		}

		// Post-process detector outputs: construct full events from outputs
		for _, output := range detectorOutputs {
			// Build complete v1beta1.Event from DetectorOutput
			event := &v1beta1.Event{
				Id:        detector.eventID,
				Name:      detector.eventName,
				Timestamp: inputEvent.Timestamp,
				Data:      output.Data,
				Workload:  inputEvent.Workload,
			}

			// Apply auto-population based on detector definition
			d.autoPopulateFields(event, inputEvent, detector)

			outputEvents = append(outputEvents, event)
		}
	}

	return outputEvents, nil
}

// autoPopulateFields applies declarative field population from detector definition.
// This enriches detector outputs based on AutoPopulateFields configuration.
func (d *dispatcher) autoPopulateFields(output, input *v1beta1.Event, detector *entry) {
	autoPop := detector.definition.AutoPopulate

	// Threat field - copy from ThreatMetadata (immutable)
	// Always copied as-is, never customized at runtime
	if autoPop.Threat && detector.definition.ThreatMetadata != nil {
		// Clone to prevent shared references
		output.Threat = cloneThreat(detector.definition.ThreatMetadata)
	}

	// DetectedFrom field - reference to input event
	// Only populate if detector hasn't set it (rare override case)
	if autoPop.DetectedFrom && output.DetectedFrom == nil {
		output.DetectedFrom = &v1beta1.DetectedFrom{
			Id:   uint32(input.Id),
			Name: input.Name,
		}
		// Copy input event data for audit trail
		if len(input.Data) > 0 {
			output.DetectedFrom.Data = make([]*v1beta1.EventValue, len(input.Data))
			copy(output.DetectedFrom.Data, input.Data)
		}
	}

	// ProcessAncestry - populate from data store (expensive, opt-in)
	// TODO: Implement when ProcessStore has GetAncestry() method
	// if autoPop.ProcessAncestry && output.Workload != nil && output.Workload.Process != nil {
	//     if len(output.Workload.Process.Ancestors) == 0 {
	//         // Query process store for ancestry (depth: 5)
	//         // output.Workload.Process.Ancestors = ...
	//     }
	// }
}

// cloneThreat creates a deep copy of Threat metadata
func cloneThreat(t *v1beta1.Threat) *v1beta1.Threat {
	if t == nil {
		return nil
	}

	clone := &v1beta1.Threat{
		Name:        t.Name,
		Description: t.Description,
		Severity:    t.Severity,
	}

	// Clone MITRE ATT&CK data
	if t.Mitre != nil {
		clone.Mitre = &v1beta1.Mitre{
			Tactic:    cloneMitreTactic(t.Mitre.Tactic),
			Technique: cloneMitreTechnique(t.Mitre.Technique),
		}
	}

	// Clone properties map
	if len(t.Properties) > 0 {
		clone.Properties = make(map[string]string, len(t.Properties))
		for k, v := range t.Properties {
			clone.Properties[k] = v
		}
	}

	return clone
}

// cloneMitreTactic clones a MITRE tactic
func cloneMitreTactic(t *v1beta1.MitreTactic) *v1beta1.MitreTactic {
	if t == nil {
		return nil
	}
	return &v1beta1.MitreTactic{
		Name: t.Name,
	}
}

// cloneMitreTechnique clones a MITRE technique
func cloneMitreTechnique(t *v1beta1.MitreTechnique) *v1beta1.MitreTechnique {
	if t == nil {
		return nil
	}
	return &v1beta1.MitreTechnique{
		Id:   t.Id,
		Name: t.Name,
	}
}
