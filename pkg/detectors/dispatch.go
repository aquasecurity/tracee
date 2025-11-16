package detectors

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
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
			// Construct full event from detector output
			event := d.buildEventFromOutput(&output, inputEvent, detector)
			outputEvents = append(outputEvents, event)

			// Track produced event (per-detector)
			d.metrics.EventsProduced.WithLabelValues(sub.detectorID).Inc()
		}
	}

	return outputEvents, nil
}

// buildEventFromOutput constructs a complete v1beta1.Event from DetectorOutput
func (d *dispatcher) buildEventFromOutput(output *detection.DetectorOutput, inputEvent *v1beta1.Event, detector *entry) *v1beta1.Event {
	// Shallow copy workload reference (read-only by contract)
	// Will be cloned only if we need to modify it (e.g., for ancestry population)
	event := &v1beta1.Event{
		Id:        detector.eventID,
		Name:      detector.eventName,
		Timestamp: inputEvent.Timestamp, // Copy from input
		Data:      output.Data,          // Detector's findings
		Workload:  inputEvent.Workload,  // Shallow reference
	}

	// Clone policies from input (preserve policy matching context)
	if inputEvent.Policies != nil {
		if cloned, ok := proto.Clone(inputEvent.Policies).(*v1beta1.Policies); ok {
			event.Policies = cloned
		} else {
			// Log warning but continue - this shouldn't happen with valid protobufs
			logger.Warnw("Failed to clone policies: unexpected type from proto.Clone",
				"detector", detector.definition.ID,
				"event", detector.eventName)
		}
	}

	// Apply auto-population with output-level overrides
	d.autoPopulateFieldsFromOutput(event, output, inputEvent, detector)

	return event
}

// autoPopulateFieldsFromOutput applies field population with output-level overrides
func (d *dispatcher) autoPopulateFieldsFromOutput(event *v1beta1.Event, output *detection.DetectorOutput, inputEvent *v1beta1.Event, detector *entry) {
	// Determine effective auto-populate settings
	// Priority: output.AutoPopulate > detector.definition.AutoPopulate
	autoPop := detector.definition.AutoPopulate
	if output.AutoPopulate != nil {
		autoPop = *output.AutoPopulate
	}

	// Threat field - priority: output.Threat > definition.ThreatMetadata
	if output.Threat != nil {
		// Detector provided custom threat
		event.Threat = cloneThreat(output.Threat)
	} else if autoPop.Threat && detector.definition.ThreatMetadata != nil {
		// Use static threat from definition
		event.Threat = cloneThreat(detector.definition.ThreatMetadata)
	}

	// DetectedFrom field - reference to input event
	// Automatically chains: output.DetectedFrom.parent = input.DetectedFrom
	if autoPop.DetectedFrom {
		event.DetectedFrom = &v1beta1.DetectedFrom{
			Id:   uint32(inputEvent.Id),
			Name: inputEvent.Name,
		}
		if len(inputEvent.Data) > 0 {
			// Copy input event data for audit trail
			event.DetectedFrom.Data = make([]*v1beta1.EventValue, len(inputEvent.Data))
			copy(event.DetectedFrom.Data, inputEvent.Data)
		}
		// Preserve detection chain: clone input's DetectedFrom (if exists)
		if inputEvent.DetectedFrom != nil {
			if cloned, ok := proto.Clone(inputEvent.DetectedFrom).(*v1beta1.DetectedFrom); ok {
				event.DetectedFrom.Parent = cloned
			}
		}
	}

	// ProcessAncestry - determine depth from output override or definition default
	// Priority: output.AncestryDepth > definition.ProcessAncestry (default 5)
	var ancestryDepth uint32
	if output.AncestryDepth != nil {
		ancestryDepth = *output.AncestryDepth
		if ancestryDepth == 0 {
			return // Explicitly disabled via AncestryDepth
		}
	} else if autoPop.ProcessAncestry {
		ancestryDepth = 5 // Default depth when ProcessAncestry boolean is true
	} else {
		return // Disabled
	}

	if event.Workload == nil || event.Workload.Process == nil {
		return
	}
	if len(event.Workload.Process.Ancestors) > 0 {
		return // Already populated by detector
	}

	entityId := event.Workload.Process.UniqueId.GetValue()
	if entityId == 0 || detector.params.DataStores == nil {
		return
	}

	ancestry, err := detector.params.DataStores.Processes().GetAncestry(entityId, int(ancestryDepth))
	if err != nil || len(ancestry) <= 1 {
		return // Error or no ancestors (only process itself)
	}

	// Clone workload now that we need to modify it
	// This is the only place where we modify the workload, so we clone lazily
	cloned, ok := proto.Clone(event.Workload).(*v1beta1.Workload)
	if !ok {
		// Log warning but continue - this shouldn't happen with valid protobufs
		logger.Warnw("Failed to clone workload for ancestry population: unexpected type from proto.Clone",
			"detector", detector.definition.ID,
			"event", detector.eventName)
		return // Skip ancestry population
	}
	event.Workload = cloned

	// Convert datastores.ProcessInfo to v1beta1.Process
	// Skip first entry (process itself, already in event.Workload.Process)
	event.Workload.Process.Ancestors = make([]*v1beta1.Process, 0, len(ancestry)-1)
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

		event.Workload.Process.Ancestors = append(event.Workload.Process.Ancestors, proc)
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
