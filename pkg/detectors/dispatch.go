package detectors

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// detectorSubscription represents a detector's subscription to an event with its filters
type detectorSubscription struct {
	detectorID  string
	scopeFilter *filters.ScopeFilter // Scope filter for this subscription (nil = no filter)
	dataFilter  *filters.DataFilter  // Data filter for this subscription (nil = no filter)
}

// dispatcher manages event routing to detectors based on their requirements
type dispatcher struct {
	mu            sync.RWMutex
	dispatchMap   map[v1beta1.EventId][]detectorSubscription // Event ID -> Detector subscriptions
	registry      *registry
	policyManager *policy.Manager
	metrics       *Metrics
}

// newDispatcher creates a new event dispatcher
func newDispatcher(registry *registry, policyManager *policy.Manager, metrics *Metrics) *dispatcher {
	return &dispatcher{
		dispatchMap:   make(map[v1beta1.EventId][]detectorSubscription),
		registry:      registry,
		policyManager: policyManager,
		metrics:       metrics,
	}
}

// rebuild reconstructs the dispatch mapping from registered detectors
// Called by the registry after Register/Unregister operations
// Only includes detectors whose output events are selected by policy
func (d *dispatcher) rebuild() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clear existing map
	d.dispatchMap = make(map[v1beta1.EventId][]detectorSubscription)

	// Build mapping from detector requirements
	d.registry.mu.RLock()
	defer d.registry.mu.RUnlock()

	for detectorID, detectorEntry := range d.registry.detectors {
		// Policy filtering: Only add detector to dispatch map if its output event is selected
		isSelected := d.policyManager != nil && d.policyManager.IsEventSelected(events.ID(detectorEntry.eventID))

		logger.Debugw("Checking detector for dispatch",
			"detector", detectorID,
			"output_event", detectorEntry.eventName,
			"event_id", detectorEntry.eventID,
			"is_selected", isSelected)

		if !isSelected {
			continue
		}

		for _, req := range detectorEntry.definition.Requirements.Events {
			// Lookup event ID by name (check predefined events first)
			var eventID v1beta1.EventId
			if predefinedID := events.LookupPredefinedEventID(req.Name); predefinedID != 0 {
				eventID = v1beta1.EventId(predefinedID)
			} else {
				// If not predefined, check if it's a detector-produced event
				// Look up in event name index to see if another detector produces it
				if producerID, exists := d.registry.eventNameIndex[req.Name]; exists {
					if producerEntry, ok := d.registry.detectors[producerID]; ok {
						eventID = producerEntry.eventID
					}
				}
			}

			logger.Debugw("Adding detector to dispatch map",
				"detector", detectorID,
				"input_event", req.Name,
				"input_event_id", eventID)

			// Create subscription with filters (if any)
			if eventID != 0 {
				subscription := detectorSubscription{
					detectorID:  detectorID,
					scopeFilter: detectorEntry.scopeFilters[eventID], // Will be nil if no filter
					dataFilter:  detectorEntry.dataFilters[eventID],  // Will be nil if no filter
				}
				d.dispatchMap[eventID] = append(d.dispatchMap[eventID], subscription)
			}
		}
	}

	logger.Debugw("Dispatcher rebuild complete",
		"dispatch_map_size", len(d.dispatchMap))
}

// dispatchToDetectors dispatches an event to all registered detectors that are interested in it
// Returns the output events produced by detectors
func (d *dispatcher) dispatchToDetectors(ctx context.Context, inputEvent *v1beta1.Event) ([]*v1beta1.Event, error) {
	var outputEvents []*v1beta1.Event

	// Stage 1: Event ID → Detector Subscriptions (dispatch mapping)
	d.mu.RLock()
	subscriptions := d.dispatchMap[inputEvent.Id]
	d.mu.RUnlock()

	// Stage 2: For each subscription, get detector entry and process
	d.registry.mu.RLock()
	defer d.registry.mu.RUnlock()

	for _, sub := range subscriptions {
		detector := d.registry.detectors[sub.detectorID]
		if detector == nil {
			continue // Should never happen, but be defensive
		}

		// Skip disabled detectors
		if !detector.enabled {
			continue
		}

		// Apply filters if any are present
		// Convert once and apply both scope and data filters
		if sub.scopeFilter != nil || sub.dataFilter != nil {
			// Convert v1beta1.Event to trace.Event for filter compatibility
			traceEvent := events.ConvertFromProto(inputEvent)

			// Apply scope filter
			if sub.scopeFilter != nil && sub.scopeFilter.Enabled() {
				if !sub.scopeFilter.Filter(*traceEvent) {
					continue // Skip if scope filter doesn't match
				}
			}

			// Apply data filter
			if sub.dataFilter != nil && sub.dataFilter.Enabled() {
				if !sub.dataFilter.Filter(traceEvent.Args) {
					continue // Skip if data filter doesn't match
				}
			}
		}

		// Track event processing (per-detector)
		d.metrics.EventsProcessed.WithLabelValues(sub.detectorID).Inc()

		// Call detector with timing
		start := time.Now()
		detectorOutputs, err := detector.detector.OnEvent(ctx, inputEvent)
		duration := time.Since(start)

		// Record execution time (per-detector)
		d.metrics.ExecutionDuration.WithLabelValues(sub.detectorID).Observe(duration.Seconds())

		if err != nil {
			// Log error and track metric, but continue processing other detectors
			// Errors are never fatal - detectors must be resilient
			d.metrics.Errors.WithLabelValues(sub.detectorID).Inc()
			logger.Debugw("Detector error",
				"detector", sub.detectorID,
				"event", inputEvent.Name,
				"error", err)
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

			// Track produced event (per-detector)
			d.metrics.EventsProduced.WithLabelValues(sub.detectorID).Inc()
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
	if !autoPop.ProcessAncestry {
		return
	}
	if output.Workload == nil || output.Workload.Process == nil {
		return
	}
	if len(output.Workload.Process.Ancestors) > 0 {
		return // Already populated by detector
	}

	entityId := output.Workload.Process.UniqueId.GetValue()
	if entityId == 0 || detector.params.DataStores == nil {
		return
	}

	const ancestryDepth = 5
	ancestry, err := detector.params.DataStores.Processes().GetAncestry(entityId, ancestryDepth)
	if err != nil || len(ancestry) <= 1 {
		return // Error or no ancestors (only process itself)
	}

	// Convert datastores.ProcessInfo to v1beta1.Process
	// Skip first entry (process itself, already in output.Workload.Process)
	output.Workload.Process.Ancestors = make([]*v1beta1.Process, 0, len(ancestry)-1)
	for _, ancestor := range ancestry[1:] {
		proc := &v1beta1.Process{
			UniqueId: &wrapperspb.UInt32Value{Value: ancestor.UniqueId},
			HostPid:  &wrapperspb.UInt32Value{Value: ancestor.HostPid},
			Pid:      &wrapperspb.UInt32Value{Value: ancestor.Pid},
		}

		// Populate thread with process name (comm)
		if ancestor.Name != "" {
			proc.Thread = &v1beta1.Thread{
				Name: ancestor.Name,
			}
		}

		// Populate executable path if available
		if ancestor.Exe != "" {
			proc.Executable = &v1beta1.Executable{
				Path: ancestor.Exe,
			}
		}

		output.Workload.Process.Ancestors = append(output.Workload.Process.Ancestors, proc)
	}
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
