package replay

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/streams"
)

func TestEventFiltering_DetectorEventsFiltered(t *testing.T) {
	// producerDetector never fires: it only exists to register
	// test_detector_event (the detector event present in mixed_events.json)
	producerDetector := createMockDetector("test_detector", "test_detector_event", nil, nil)

	// watcherDetector fires on test_detector_event: if the file-supplied
	// detector event were dispatched instead of filtered, it would produce
	// output and fail the test
	watcherDetector := createMockDetector("filter_watcher", "filter_watcher_output", []string{"test_detector_event"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			return []detection.DetectorOutput{
				{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("leaked", "true")}},
			}, nil
		})

	setup := setupReplayTest(t, "testdata/mixed_events.json",
		[]detection.EventDetector{producerDetector, watcherDetector},
		[]string{"test_detector_event", "filter_watcher_output"}, createDefaultPrinter())
	defer setup.sourceFile.Close()

	runReplay(t, setup.cfg, 5*time.Second)

	for _, event := range setup.printedEvents {
		assert.NotEqual(t, "filter_watcher_output", event.Name,
			"detector events from the file must be filtered out before dispatch")
		assert.NotEqual(t, "test_detector_event", event.Name,
			"file-supplied detector events must never be printed")
	}
}

func TestEventFiltering_LowLevelEventsProcessed(t *testing.T) {
	// Fires on both low-level events in the file, proving they are dispatched
	watcherDetector := createMockDetector("lowlevel_watcher", "lowlevel_watcher_output", []string{"execve", "openat"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			return []detection.DetectorOutput{
				{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("seen", event.Name)}},
			}, nil
		})

	setup := setupReplayTest(t, "testdata/low_level_events.json",
		[]detection.EventDetector{watcherDetector},
		[]string{"execve", "openat", "lowlevel_watcher_output"}, createDefaultPrinter())
	defer setup.sourceFile.Close()

	runReplay(t, setup.cfg, 5*time.Second)

	// Both low-level events are processed (the detector fired for each), but
	// only detector outputs are printed, never the raw events themselves
	outputs := 0
	for _, event := range setup.printedEvents {
		assert.NotContains(t, []string{"execve", "openat"}, event.Name,
			"low-level events must not be printed, only detector outputs")
		if event.Name == "lowlevel_watcher_output" {
			outputs++
		}
	}
	assert.Equal(t, 2, outputs, "the detector should fire once per low-level event in the file")
}

func TestReplay_DetectorProducesOutput(t *testing.T) {
	detectorOutputs := []*v1beta1.Event{}
	outputDetector := createMockDetector("output_detector", "detector_output", []string{"execve"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			if event.Name == "execve" {
				return []detection.DetectorOutput{
					{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("detected", "true")}},
				}, nil
			}
			return nil, nil
		})

	// Create custom printer to track detector outputs
	customPrinter := &mockEventPrinter{
		printFunc: func(event *v1beta1.Event) {
			if event.Name == "detector_output" {
				detectorOutputs = append(detectorOutputs, event)
			}
		},
	}

	setup := setupReplayTest(t, "testdata/low_level_events.json", []detection.EventDetector{outputDetector}, []string{"execve", "detector_output"}, customPrinter)
	defer setup.sourceFile.Close()

	runReplay(t, setup.cfg, 5*time.Second)

	// Verify detector produced output
	assert.Greater(t, len(detectorOutputs), 0, "Detector should produce output for execve event")
	if len(detectorOutputs) > 0 {
		detected, found := v1beta1.GetData[string](detectorOutputs[0], "detected")
		assert.True(t, found, "Detector output should contain detected field")
		assert.Equal(t, "true", detected)
	}
}

func TestReplay_DetectorChaining(t *testing.T) {
	// Create first detector that produces output on execve
	firstDetector := createMockDetector("first_detector", "first_detector_output", []string{"execve"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			if event.Name == "execve" {
				return []detection.DetectorOutput{
					{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("level", "1")}},
				}, nil
			}
			return nil, nil
		})

	// Create second detector that triggers on first detector's output
	secondDetector := createMockDetector("second_detector", "second_detector_output", []string{"first_detector_output"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			if event.Name == "first_detector_output" {
				return []detection.DetectorOutput{
					{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("level", "2")}},
				}, nil
			}
			return nil, nil
		})

	detectorsList := []detection.EventDetector{firstDetector, secondDetector}

	// Track detector outputs
	firstOutputs := []*v1beta1.Event{}
	secondOutputs := []*v1beta1.Event{}

	// Create custom printer to track specific outputs
	customPrinter := &mockEventPrinter{
		printFunc: func(event *v1beta1.Event) {
			if event.Name == "first_detector_output" {
				firstOutputs = append(firstOutputs, event)
			} else if event.Name == "second_detector_output" {
				secondOutputs = append(secondOutputs, event)
			}
		},
	}

	setup := setupReplayTest(t, "testdata/low_level_events.json", detectorsList, []string{"execve", "first_detector_output", "second_detector_output"}, customPrinter)
	defer setup.sourceFile.Close()

	runReplay(t, setup.cfg, 5*time.Second)

	// Verify first detector produced output
	assert.Greater(t, len(firstOutputs), 0, "First detector should produce output")
	// Verify second detector was triggered by first detector's output (chaining)
	assert.Greater(t, len(secondOutputs), 0, "Second detector should be triggered by first detector output (chaining)")
}

func TestReplay_DetectorChaining_LargeFile(t *testing.T) {
	// Regression test: with more events than the channel buffer, tail events
	// used to be handled by a drain path that skipped detector chaining
	const numEvents = 3 * eventChanBufferSize

	inputEvents := make([]*v1beta1.Event, numEvents)
	for i := range inputEvents {
		inputEvents[i] = &v1beta1.Event{
			Timestamp: timestamppb.Now(),
			Id:        v1beta1.EventId_execve,
			Name:      "execve",
		}
	}
	path := writeEventsFile(t, inputEvents)

	firstDetector := createMockDetector("first_detector_lf", "first_detector_lf_output", []string{"execve"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			if event.Name == "execve" {
				return []detection.DetectorOutput{
					{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("level", "1")}},
				}, nil
			}
			return nil, nil
		})
	secondDetector := createMockDetector("second_detector_lf", "second_detector_lf_output", []string{"first_detector_lf_output"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			if event.Name == "first_detector_lf_output" {
				return []detection.DetectorOutput{
					{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("level", "2")}},
				}, nil
			}
			return nil, nil
		})

	detectorsList := []detection.EventDetector{firstDetector, secondDetector}
	setup := setupReplayTest(t, path, detectorsList,
		[]string{"execve", "first_detector_lf_output", "second_detector_lf_output"}, createDefaultPrinter())
	defer setup.sourceFile.Close()

	runReplay(t, setup.cfg, 10*time.Second)

	firstCount, secondCount := 0, 0
	for _, event := range setup.printedEvents {
		switch event.Name {
		case "first_detector_lf_output":
			firstCount++
		case "second_detector_lf_output":
			secondCount++
		default:
		}
	}
	assert.Equal(t, numEvents, firstCount, "every input event should trigger the first detector")
	assert.Equal(t, numEvents, secondCount, "every first detector output should chain into the second detector")
}

func TestReplay_DetectorCycleTerminates(t *testing.T) {
	// Regression test: a detector triggered by its own output must not loop
	// forever; the chain is bounded by maxDetectorChainDepth as in the live
	// pipeline.
	selfDetector := createMockDetector("cycle_detector", "cycle_detector_output",
		[]string{"execve", "cycle_detector_output"},
		func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
			return []detection.DetectorOutput{
				{Data: []*v1beta1.EventValue{v1beta1.NewStringValue("looping", "yes")}},
			}, nil
		})

	setup := setupReplayTest(t, "testdata/low_level_events.json",
		[]detection.EventDetector{selfDetector},
		[]string{"execve", "cycle_detector_output"}, createDefaultPrinter())
	defer setup.sourceFile.Close()

	runReplay(t, setup.cfg, 10*time.Second)

	// low_level_events.json holds one execve (and one openat, which is not a
	// requirement): the initial dispatch fires once, then one chained output
	// per depth level until the cap cuts the cycle
	outputs := 0
	for _, event := range setup.printedEvents {
		if event.Name == "cycle_detector_output" {
			outputs++
		}
	}
	assert.Equal(t, 1+maxDetectorChainDepth, outputs,
		"cycle must be cut off by the chain depth cap")
}

// verify mockEventPrinter implements the interface
var _ printer.EventPrinter = (*mockEventPrinter)(nil)

// verify mockDetector implements the interface
var _ detection.EventDetector = (*mockDetector)(nil)

// createDefaultPrinter creates a simple printer that tracks all printed events
func createDefaultPrinter() *mockEventPrinter {
	return &mockEventPrinter{
		printFunc: func(event *v1beta1.Event) {
			// Simple printer that does nothing by default
		},
	}
}

// mockDetector implements detection.EventDetector for testing
type mockDetector struct {
	id           string
	eventName    string
	requirements detection.DetectorRequirements
	onEventFunc  func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error)
}

func (m *mockDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID:            m.id,
		ProducedEvent: v1beta1.EventDefinition{Name: m.eventName},
		Requirements:  m.requirements,
	}
}

func (m *mockDetector) Init(params detection.DetectorParams) error {
	return nil
}

func (m *mockDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	if m.onEventFunc != nil {
		return m.onEventFunc(ctx, event)
	}
	return nil, nil
}

func (m *mockDetector) Close() error {
	return nil
}

// mockEventPrinter implements printer.EventPrinter for testing
type mockEventPrinter struct {
	printFunc func(*v1beta1.Event)
}

func (m *mockEventPrinter) Init() error { return nil }
func (m *mockEventPrinter) Preamble()   {}
func (m *mockEventPrinter) Print(event *v1beta1.Event) {
	if m.printFunc != nil {
		m.printFunc(event)
	}
}
func (m *mockEventPrinter) Epilogue(stats metrics.Stats)      {}
func (m *mockEventPrinter) FromStream(stream *streams.Stream) {}
func (m *mockEventPrinter) Kind() string                      { return "mock" }
func (m *mockEventPrinter) Close()                            {}

// testSetup holds common test infrastructure
type testSetup struct {
	sourceFile    *os.File
	policyMgr     *policy.Manager
	printedEvents []*v1beta1.Event
	cfg           Config
}

// setupReplayTest sets up complete test infrastructure:
// - Opens testdata file
// - Creates policy manager
// - Registers detector events (if detectors provided)
// - Enables events in policy manager
// - Wraps provided printer to track events
// - Returns Config ready to use
func setupReplayTest(t *testing.T, testdataFile string, detectorList []detection.EventDetector, eventsToEnable []string, eventPrinter printer.EventPrinter) *testSetup {
	t.Helper()

	logger.Init(logger.NewDefaultLoggingConfig())

	// Open testdata file
	sourceFile, err := os.Open(testdataFile)
	require.NoError(t, err)
	// Seek to beginning in case file was already read
	_, err = sourceFile.Seek(0, 0)
	require.NoError(t, err)

	// Create dependencies manager and policy manager
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyMgr, err := policy.NewManager(policy.ManagerConfig{}, depsManager)
	require.NoError(t, err)

	// Register detector events if detectors are provided
	if len(detectorList) > 0 {
		// Check which detector events need to be registered
		detectorsToRegister := []detection.EventDetector{}
		for _, det := range detectorList {
			eventName := det.GetDefinition().ProducedEvent.Name
			_, found := events.Core.GetDefinitionIDByName(eventName)
			if !found {
				detectorsToRegister = append(detectorsToRegister, det)
			}
		}

		if len(detectorsToRegister) > 0 {
			startID := findNextAvailableDetectorID()
			_, err := detectors.CreateEventsFromDetectors(startID, detectorsToRegister)
			require.NoError(t, err, "Failed to register detector events")
		}
	}

	// Enable events in policy manager
	for _, eventName := range eventsToEnable {
		eventID, found := events.Core.GetDefinitionIDByName(eventName)
		if !found {
			// Try translating from protobuf event ID for built-in events
			switch eventName {
			case "execve":
				eventID = events.TranslateFromProtoEventID(v1beta1.EventId_execve)
			case "openat":
				eventID = events.TranslateFromProtoEventID(v1beta1.EventId_openat)
			default:
				t.Fatalf("Event '%s' not found", eventName)
			}
		}
		policyMgr.EnableEvent(eventID)
	}

	setup := &testSetup{
		sourceFile: sourceFile,
		policyMgr:  policyMgr,
	}

	// Wrap provided printer to track printed events in setup.printedEvents
	setup.cfg = Config{
		Source: sourceFile,
		Printer: &mockEventPrinter{
			printFunc: func(event *v1beta1.Event) {
				setup.printedEvents = append(setup.printedEvents, event)
				eventPrinter.Print(event)
			},
		},
		Detectors:         detectorList,
		PolicyManager:     policyMgr,
		EnrichmentOptions: &detectors.EnrichmentOptions{},
	}

	return setup
}

// createMockDetector creates a mock detector with optional onEventFunc
func createMockDetector(id, eventName string, requiredEvents []string, onEventFunc func(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error)) *mockDetector {
	reqs := detection.DetectorRequirements{}
	if len(requiredEvents) > 0 {
		reqs.Events = make([]detection.EventRequirement, len(requiredEvents))
		for i, evt := range requiredEvents {
			reqs.Events[i] = detection.EventRequirement{Name: evt}
		}
	}

	return &mockDetector{
		id:           id,
		eventName:    eventName,
		requirements: reqs,
		onEventFunc:  onEventFunc,
	}
}

// runReplay runs the replay function and waits for completion with timeout
func runReplay(t *testing.T, cfg Config, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Replay(ctx, cfg)
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "Replay failed")
	case <-ctx.Done():
		t.Fatal("Replay timed out")
	}
}

// findNextAvailableDetectorID finds the next available detector event ID
func findNextAvailableDetectorID() events.ID {
	// Start from StartDetectorID and find the first unused ID
	for id := events.StartDetectorID; id <= events.MaxDetectorID; id++ {
		if !events.Core.IsDefined(id) {
			return id
		}
	}
	// If all IDs are taken, return MaxDetectorID (shouldn't happen in tests)
	return events.MaxDetectorID
}
