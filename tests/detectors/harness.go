package detectors

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/types/trace"
)

// nextTestEventID is used to allocate unique event IDs across tests
// to avoid conflicts in the global events.Core registry.
// Range: 7500-7999 (500 IDs total for detectors)
var nextTestEventID atomic.Uint32

// idsPerHarness is the number of event IDs allocated per test harness.
// This allows ~50 harnesses within the 7500-7999 range.
const idsPerHarness = 10

func init() {
	// Start from events.StartDetectorID (7500)
	nextTestEventID.Store(uint32(events.StartDetectorID))
}

// TestHarness provides a complete testing environment for detectors
type TestHarness struct {
	Engine      *detectors.Engine
	Context     context.Context
	T           *testing.T
	EventIDMap  map[string]events.ID // Event name → ID mapping
	nextEventID events.ID            // For allocating detector event IDs
	policyMgr   *policy.Manager      // Policy manager for enabling events
}

// NewTestHarness creates a new detector testing harness
// selectedEvents are the kernel/base events that detectors will consume
func NewTestHarness(t *testing.T, selectedEvents ...events.ID) *TestHarness {
	// Allocate unique event ID range for this test
	startID := events.ID(nextTestEventID.Add(idsPerHarness)) - idsPerHarness

	// Create dependencies manager
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// Create policy manager
	policyMgr, err := policy.NewManager(policy.ManagerConfig{}, depsManager)
	require.NoError(t, err, "Failed to create policy manager")

	// Enable selected events in policy
	for _, eventID := range selectedEvents {
		policyMgr.EnableEvent(eventID)
	}

	// Create detector engine
	engine := detectors.NewEngine(policyMgr, nil)

	return &TestHarness{
		Engine:      engine,
		Context:     context.Background(),
		T:           t,
		EventIDMap:  make(map[string]events.ID),
		nextEventID: startID,
		policyMgr:   policyMgr,
	}
}

// RegisterDetector registers a detector and its produced event
func (h *TestHarness) RegisterDetector(detector detection.EventDetector) error {
	def := detector.GetDefinition()

	// Allocate event ID for detector's produced event
	eventID := h.nextEventID
	h.nextEventID++

	// Register event in events.Core
	eventDef := events.NewDefinition(
		eventID,
		events.Sys32Undefined,
		def.ProducedEvent.Name,
		convertVersion(def.ProducedEvent.Version),
		def.ProducedEvent.Description,
		false, // internal
		false, // syscall
		[]string{"detectors", "test"},
		events.NewDependencyStrategy(events.Dependencies{}),
		convertFieldsToDataFields(def.ProducedEvent.Fields),
		map[string]interface{}{"detectorID": def.ID},
	)

	if err := events.Core.Add(eventID, eventDef); err != nil {
		return err
	}

	// Store mapping
	h.EventIDMap[def.ProducedEvent.Name] = eventID

	// Enable detector's output event in policy
	// This is required for the detector to be included in the dispatch map
	h.policyMgr.EnableEvent(eventID)

	// Register detector with engine
	err := h.Engine.RegisterDetector(detector, detection.DetectorParams{
		Logger: &testLogger{t: h.T},
		Config: detection.NewEmptyDetectorConfig(),
	})
	if err != nil {
		return err
	}

	return nil
}

// DispatchEvent sends an event to registered detectors and returns outputs
func (h *TestHarness) DispatchEvent(event *v1beta1.Event) []*v1beta1.Event {
	outputs, err := h.Engine.DispatchToDetectors(h.Context, event)
	require.NoError(h.T, err, "DispatchToDetectors failed")
	return outputs
}

// FindOutputByName finds an output event by name (useful for chains)
func (h *TestHarness) FindOutputByName(outputs []*v1beta1.Event, name string) *v1beta1.Event {
	for _, output := range outputs {
		if output.Name == name {
			return output
		}
	}
	return nil
}

// AssertOutputCount asserts the number of output events
func (h *TestHarness) AssertOutputCount(outputs []*v1beta1.Event, expected int) {
	assert.Len(h.T, outputs, expected, "Expected %d output events, got %d", expected, len(outputs))
}

// AssertOutputEvent asserts an output event has the expected name
func (h *TestHarness) AssertOutputEvent(output *v1beta1.Event, expectedName string) {
	require.NotNil(h.T, output, "Output event is nil")
	assert.Equal(h.T, expectedName, output.Name, "Expected event name %s, got %s", expectedName, output.Name)
}

// AssertThreatPopulated asserts the Threat field is populated
func (h *TestHarness) AssertThreatPopulated(output *v1beta1.Event) {
	require.NotNil(h.T, output, "Output event is nil")
	require.NotNil(h.T, output.Threat, "Threat field is not populated")
	assert.NotEmpty(h.T, output.Threat.Name, "Threat name is empty")
}

// AssertDetectedFromPopulated asserts DetectedFrom references the input event
func (h *TestHarness) AssertDetectedFromPopulated(output *v1beta1.Event, inputEventName string) {
	require.NotNil(h.T, output, "Output event is nil")
	require.NotNil(h.T, output.DetectedFrom, "DetectedFrom field is not populated")
	assert.Equal(h.T, inputEventName, output.DetectedFrom.Name, "DetectedFrom event name mismatch")
}

// Helper functions

// convertVersion converts v1beta1.Version to events.Version
func convertVersion(v *v1beta1.Version) events.Version {
	if v == nil {
		return events.NewVersion(1, 0, 0)
	}
	return events.NewVersion(v.Major, v.Minor, v.Patch)
}

// convertFieldsToDataFields converts v1beta1.EventField to events.DataField
func convertFieldsToDataFields(fields []*v1beta1.EventField) []events.DataField {
	if len(fields) == 0 {
		return nil
	}

	dataFields := make([]events.DataField, 0, len(fields))
	for _, f := range fields {
		dataFields = append(dataFields, events.DataField{
			ArgMeta: trace.ArgMeta{
				Name: f.Name,
				Type: f.Type,
			},
		})
	}
	return dataFields
}

// testLogger is a simple logger for testing
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.t.Logf("[DEBUG] %s %v", msg, keysAndValues)
}

func (l *testLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.t.Logf("[INFO] %s %v", msg, keysAndValues)
}

func (l *testLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.t.Logf("[WARN] %s %v", msg, keysAndValues)
}

func (l *testLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.t.Logf("[ERROR] %s %v", msg, keysAndValues)
}
