package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// nextDetectorEventID is used to allocate unique event IDs across tests
// to avoid conflicts in the global events.Core registry
var nextDetectorEventID atomic.Uint32

func init() {
	// Start from events.StartDetectorID (7000)
	nextDetectorEventID.Store(uint32(events.StartDetectorID))
}

// Helper functions

// createTempYAMLDetector creates a temporary YAML detector file for testing
func createTempYAMLDetector(t *testing.T, yamlDir, filename, content string) {
	detectorPath := filepath.Join(yamlDir, filename)
	err := os.WriteFile(detectorPath, []byte(content), 0644)
	require.NoError(t, err, "Failed to create temp YAML detector")
}

// startTraceeWithYAMLDetectors starts Tracee with YAML detector directory configured
func startTraceeWithYAMLDetectors(ctx context.Context, t *testing.T, yamlDir string) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	// Load YAML detectors from test directory
	yamlDets, errors := yamldetectors.LoadFromDirectories([]string{yamlDir})
	if len(errors) > 0 {
		for _, err := range errors {
			t.Logf("Warning: Failed to load YAML detector: %v", err)
		}
	}

	// Allocate unique event IDs for this test to avoid conflicts in global events.Core
	// Each test gets its own range of IDs
	startID := events.ID(nextDetectorEventID.Add(uint32(len(yamlDets))))
	startID -= events.ID(len(yamlDets)) // Adjust back to the start of this test's range

	// Pre-register YAML detector events in events.Core before starting Tracee
	// This is required for detector registration to succeed
	eventNameToID, err := detectors.CreateEventsFromDetectors(startID, yamlDets)
	require.NoError(t, err, "Failed to create detector events")

	// Build list of all events to select: detector outputs + their input dependencies
	eventsToSelect := make([]events.ID, 0)

	// Add detector output events
	for _, eventID := range eventNameToID {
		eventsToSelect = append(eventsToSelect, eventID)
	}

	// Add input events that detectors depend on
	inputEventNames := make(map[string]bool)
	for _, det := range yamlDets {
		def := det.GetDefinition()
		for _, req := range def.Requirements.Events {
			inputEventNames[req.Name] = true
		}
	}

	// Convert input event names to IDs
	for eventName := range inputEventNames {
		if eventID, found := events.Core.GetDefinitionIDByName(eventName); found {
			eventsToSelect = append(eventsToSelect, eventID)
		}
	}

	// Create policy to select all required events
	policies := testutils.BuildPoliciesFromEvents(eventsToSelect)
	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}

	cfg := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		InitialPolicies: initialPolicies, // Select detector output events
		DetectorConfig: config.DetectorConfig{
			Detectors:      yamlDets, // Only use YAML detectors for testing
			YAMLSearchDirs: []string{yamlDir},
		},
	}

	// Start Tracee (this starts Run() in a goroutine but returns immediately)
	trc, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	// Subscribe BEFORE waiting for Tracee to start - this ensures no events are dropped
	// (Detector events can be emitted as soon as input events are captured)
	stream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)

	// NOW wait for Tracee to be fully running
	err = testutils.WaitForTraceeStart(trc)
	require.NoError(t, err, "Tracee failed to start")

	// Start goroutine to collect events
	buf := testutils.NewEventBuffer()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-stream.ReceiveEvents():
				if evt != nil {
					buf.AddEvent(evt)
				}
			}
		}
	}()

	return trc, buf, stream
}

// waitForDetectorEvent waits for a specific detector event to appear in the buffer
func waitForDetectorEvent(buf *testutils.EventBuffer, eventName string, timeout time.Duration) *pb.Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		eventList := buf.GetCopy()
		for i := range eventList {
			if eventList[i] != nil && eventList[i].Name == eventName {
				return eventList[i]
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// getArgValue extracts an argument value from a protobuf event by name
func getArgValue(evt *pb.Event, argName string) interface{} {
	if evt == nil || evt.Data == nil {
		return nil
	}
	for _, data := range evt.Data {
		if data.Name == argName {
			// Extract the actual value from the oneof field
			switch v := data.Value.(type) {
			case *pb.EventValue_Int32:
				return v.Int32
			case *pb.EventValue_Int64:
				return v.Int64
			case *pb.EventValue_UInt32:
				return v.UInt32
			case *pb.EventValue_UInt64:
				return v.UInt64
			case *pb.EventValue_Str:
				return v.Str
			case *pb.EventValue_Bytes:
				return v.Bytes
			case *pb.EventValue_Bool:
				return v.Bool
			case *pb.EventValue_StrArray:
				return v.StrArray
			default:
				return nil
			}
		}
	}
	return nil
}

// Test Cases

// Test_YAMLDetectorBasicLoading tests that YAML detectors are discovered and loaded correctly
func Test_YAMLDetectorBasicLoading(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Create a simple YAML detector
	detectorYAML := `id: yaml-test-001
produced_event:
  name: test_basic_loading
  version: 1.0.0
  description: Test detector for basic loading
  tags:
    - test
  fields:
    - name: test_field
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/bin/true

auto_populate:
  detected_from: true

output:
  fields:
    - name: test_field
      expression: getData("pathname")
`

	createTempYAMLDetector(t, yamlDir, "test_basic.yaml", detectorYAML)

	// Load detectors and verify YAML detector is included
	allDetectors := detectors.CollectAllDetectors([]string{yamlDir})

	// Verify at least one YAML detector was loaded
	found := false
	for _, det := range allDetectors {
		def := det.GetDefinition()
		if def.ID == "yaml-test-001" {
			found = true
			assert.Equal(t, "test_basic_loading", def.ProducedEvent.Name)
			assert.Equal(t, "Test detector for basic loading", def.ProducedEvent.Description)
			break
		}
	}

	assert.True(t, found, "YAML detector yaml-test-001 should be loaded")
	t.Logf("Successfully loaded YAML detector yaml-test-001")
}

// Test_YAMLDetectorEventGeneration tests that a YAML detector produces events with correct field extraction
func Test_YAMLDetectorEventGeneration(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Create a detector that extracts multiple fields
	detectorYAML := `id: yaml-test-002
produced_event:
  name: test_event_generation
  version: 1.0.0
  description: Test detector for event generation
  tags:
    - test
  fields:
    - name: binary_path
      type: string
    - name: binary_name
      type: string
    - name: pid
      type: uint32

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/usr/bin/true

auto_populate:
  detected_from: true

output:
  fields:
    - name: binary_path
      expression: getData("pathname")
    - name: binary_name
      expression: workload.process.thread.name
    - name: pid
      expression: workload.process.pid
`

	createTempYAMLDetector(t, yamlDir, "test_event_gen.yaml", detectorYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectors(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	t.Logf("Tracee started, triggering detection...")

	// Trigger the detector by executing /usr/bin/true
	cmd := exec.Command("/usr/bin/true")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/true")

	// Wait for the detector event
	evt := waitForDetectorEvent(buf, "test_event_generation", 5*time.Second)
	require.NotNil(t, evt, "Expected test_event_generation event not found")

	t.Logf("Found event: %s", evt.Name)

	// Verify extracted fields
	binaryPath := getArgValue(evt, "binary_path")
	assert.NotNil(t, binaryPath, "binary_path should be extracted")
	assert.Contains(t, binaryPath, "/usr/bin/true", "binary_path should contain /usr/bin/true")

	binaryName := getArgValue(evt, "binary_name")
	assert.NotNil(t, binaryName, "binary_name should be extracted")
	assert.Equal(t, "true", binaryName, "binary_name should be 'true'")

	pid := getArgValue(evt, "pid")
	assert.NotNil(t, pid, "pid should be extracted")
	assert.Greater(t, pid, uint32(0), "pid should be greater than 0")

	t.Logf("Field extraction verified: binary_path=%v, binary_name=%v, pid=%v", binaryPath, binaryName, pid)
}

// Test_YAMLDetectorChaining tests that YAML detectors can consume events from other YAML detectors
func Test_YAMLDetectorChaining(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Level 1: Base detector that detects exec of /usr/bin/id
	level1YAML := `id: yaml-chain-level1
produced_event:
  name: test_exec_detected
  version: 1.0.0
  description: Base detector for chaining test
  tags:
    - test
  fields:
    - name: binary_path
      type: string
    - name: pid
      type: uint32

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/usr/bin/id

auto_populate:
  detected_from: true

output:
  fields:
    - name: binary_path
      expression: getData("pathname")
    - name: pid
      expression: workload.process.pid
`

	// Level 2: Composed detector that consumes level 1 output
	level2YAML := `id: yaml-chain-level2
produced_event:
  name: test_exec_enriched
  version: 1.0.0
  description: Composed detector for chaining test
  tags:
    - test
  fields:
    - name: original_path
      type: string
    - name: original_pid
      type: uint32

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: test_exec_detected
      dependency: required

threat:
  severity: medium
  description: Test chained detection

auto_populate:
  threat: true
  detected_from: true

output:
  fields:
    - name: original_path
      expression: getData("binary_path")
    - name: original_pid
      expression: getData("pid")
`

	createTempYAMLDetector(t, yamlDir, "chain_level1.yaml", level1YAML)
	createTempYAMLDetector(t, yamlDir, "chain_level2.yaml", level2YAML)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectors(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	t.Logf("Tracee started with chained detectors, triggering detection...")

	// Trigger the detector chain by executing /usr/bin/id
	cmd := exec.Command("/usr/bin/id")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/id")

	// Wait for both level 1 and level 2 events
	level1Evt := waitForDetectorEvent(buf, "test_exec_detected", 5*time.Second)
	require.NotNil(t, level1Evt, "Expected level 1 event test_exec_detected not found")
	t.Logf("Found level 1 event: %s", level1Evt.Name)

	level2Evt := waitForDetectorEvent(buf, "test_exec_enriched", 5*time.Second)
	require.NotNil(t, level2Evt, "Expected level 2 event test_exec_enriched not found")
	t.Logf("Found level 2 event: %s", level2Evt.Name)

	// Verify level 1 extracted fields
	level1Path := getArgValue(level1Evt, "binary_path")
	assert.NotNil(t, level1Path, "level 1 binary_path should be extracted")
	assert.Contains(t, level1Path, "/usr/bin/id", "level 1 binary_path should contain /usr/bin/id")

	// Verify level 2 extracted fields (should come from level 1 data)
	level2Path := getArgValue(level2Evt, "original_path")
	assert.NotNil(t, level2Path, "level 2 original_path should be extracted")
	assert.Equal(t, level1Path, level2Path, "level 2 should extract data from level 1")

	level2Pid := getArgValue(level2Evt, "original_pid")
	assert.NotNil(t, level2Pid, "level 2 original_pid should be extracted")

	t.Logf("Detector chaining verified: level1_path=%v, level2_path=%v, level2_pid=%v", level1Path, level2Path, level2Pid)
}

// Test_YAMLDetectorFilters tests that data_filters and scope_filters work correctly
func Test_YAMLDetectorFilters(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Create a detector with specific pathname filter
	detectorYAML := `id: yaml-test-filters
produced_event:
  name: test_filter_match
  version: 1.0.0
  description: Test detector for filter verification
  tags:
    - test
  fields:
    - name: matched_path
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/usr/bin/cat

auto_populate:
  detected_from: true

output:
  fields:
    - name: matched_path
      expression: getData("pathname")
`

	createTempYAMLDetector(t, yamlDir, "test_filters.yaml", detectorYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectors(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	t.Logf("Tracee started, testing filters...")

	// Clear buffer before tests
	buf.Clear()

	// Test 1: Execute matching pathname - should fire
	t.Logf("Test 1: Executing /usr/bin/cat (should match filter)")
	cmd := exec.Command("/usr/bin/cat", "/dev/null")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/cat")

	time.Sleep(1 * time.Second)

	matchedEvt := waitForDetectorEvent(buf, "test_filter_match", 3*time.Second)
	assert.NotNil(t, matchedEvt, "Detector should fire for matching pathname /usr/bin/cat")

	if matchedEvt != nil {
		matchedPath := getArgValue(matchedEvt, "matched_path")
		assert.Contains(t, matchedPath, "/usr/bin/cat", "matched_path should contain /usr/bin/cat")
		t.Logf("✓ Filter matched correctly for /usr/bin/cat")
	}

	// Clear buffer for next test
	buf.Clear()

	// Test 2: Execute non-matching pathname - should NOT fire
	t.Logf("Test 2: Executing /usr/bin/id (should NOT match filter)")
	cmd = exec.Command("/usr/bin/id")
	err = cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/id")

	time.Sleep(1 * time.Second)

	unmatchedEvt := waitForDetectorEvent(buf, "test_filter_match", 2*time.Second)
	assert.Nil(t, unmatchedEvt, "Detector should NOT fire for non-matching pathname /usr/bin/id")
	t.Logf("✓ Filter correctly rejected /usr/bin/id")
}

// Test_YAMLDetectorErrorHandling tests graceful handling of invalid YAML and missing fields
func Test_YAMLDetectorErrorHandling(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Test 1: Invalid YAML syntax - should be logged but not crash
	invalidYAML := `id: yaml-invalid
produced_event:
  name: invalid_event
  version: 1.0.0
  invalid syntax here [[[
requirements:
  events:
    - name: sched_process_exec
`

	createTempYAMLDetector(t, yamlDir, "invalid_syntax.yaml", invalidYAML)

	// Test 2: Valid YAML but missing required ID field
	missingIDYAML := `produced_event:
  name: missing_id_event
  version: 1.0.0
  description: Missing ID field
requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
`

	createTempYAMLDetector(t, yamlDir, "missing_id.yaml", missingIDYAML)

	// Test 3: Valid detector that should load successfully
	validYAML := `id: yaml-test-valid
produced_event:
  name: test_valid_event
  version: 1.0.0
  description: Valid detector
  tags:
    - test
  fields:
    - name: test_field
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/bin/pwd

auto_populate:
  detected_from: true

output:
  fields:
    - name: test_field
      expression: getData("pathname")
`

	createTempYAMLDetector(t, yamlDir, "valid.yaml", validYAML)

	// Load detectors - invalid ones should be skipped with warnings
	allDetectors := detectors.CollectAllDetectors([]string{yamlDir})

	// Verify that the valid detector was loaded
	validFound := false
	invalidFound := false
	missingIDFound := false

	for _, det := range allDetectors {
		def := det.GetDefinition()
		switch def.ID {
		case "yaml-test-valid":
			validFound = true
		case "yaml-invalid":
			invalidFound = true
		case "": // missing ID case
			missingIDFound = true
		}
	}

	assert.True(t, validFound, "Valid detector should be loaded")
	assert.False(t, invalidFound, "Invalid syntax detector should NOT be loaded")
	assert.False(t, missingIDFound, "Missing ID detector should NOT be loaded")

	t.Logf("✓ Error handling verified: valid loaded, invalid rejected")

	// Test 4: Missing required field during extraction should skip detection gracefully
	detectorWithRequiredField := `id: yaml-test-required-field
produced_event:
  name: test_required_field
  version: 1.0.0
  description: Test required field handling
  tags:
    - test
  fields:
    - name: required_field
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/bin/hostname

auto_populate:
  detected_from: true

output:
  fields:
    - name: required_field
      expression: getData("nonexistent_field")
`

	createTempYAMLDetector(t, yamlDir, "required_field.yaml", detectorWithRequiredField)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectors(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	t.Logf("Tracee started, testing missing required field...")

	// Trigger the detector
	cmd := exec.Command("/bin/hostname")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /bin/hostname")

	time.Sleep(1 * time.Second)

	// The detector should NOT produce an event because required field is missing
	evt := waitForDetectorEvent(buf, "test_required_field", 2*time.Second)
	assert.Nil(t, evt, "Detector should skip detection when required field is missing")

	t.Logf("✓ Missing required field handled gracefully (detection skipped)")
}
