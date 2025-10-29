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

			// TODO: Apply auto-population (Threat, DetectedFrom, Policies) based on detector definition

			outputEvents = append(outputEvents, event)
		}
	}

	return outputEvents, nil
}
