package integration

import (
	"context"
	"fmt"
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
	"github.com/aquasecurity/tracee/common/logger"
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

// startTraceeWithYAMLDetectors starts Tracee with YAML detector directory configured. It selects the
// detector output events AND their input (base) events. Selecting the base events explicitly creates a
// broad (unscoped) policy rule on them - fine for tests that only check detector firing, but it
// UNION-DEFEATS any detector-declared kernel scope filter on those base events. Kernel-pushdown tests
// must use startTraceeWithYAMLDetectorsScoped instead.
func startTraceeWithYAMLDetectors(ctx context.Context, t *testing.T, yamlDir string) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	return startTraceeWithYAMLDetectorsEx(ctx, t, yamlDir, true)
}

// startTraceeWithYAMLDetectorsScoped selects ONLY the detector output events. Each detector's required
// base events are then pulled in solely as SCOPED dependencies (a detector output declares its
// requirements as event dependencies), with no competing broad policy rule. This is what makes a
// detector-declared kernel scope filter actually gate submission - required for the kernel-pushdown
// tests, where EventsFiltered==0 must mean "dropped in the kernel", not "matched a broad rule".
func startTraceeWithYAMLDetectorsScoped(ctx context.Context, t *testing.T, yamlDir string) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	return startTraceeWithYAMLDetectorsEx(ctx, t, yamlDir, false)
}

func startTraceeWithYAMLDetectorsEx(ctx context.Context, t *testing.T, yamlDir string, selectInputs bool) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	// Load YAML detectors from test directory
	result := yamldetectors.LoadFromDirectories([]string{yamlDir})
	// Errors are expected in error handling tests and suppressed via logger setup

	// Allocate unique event IDs for this test to avoid conflicts in global events.Core
	// Each test gets its own range of IDs
	startID := events.ID(nextDetectorEventID.Add(uint32(len(result.Detectors))))
	startID -= events.ID(len(result.Detectors)) // Adjust back to the start of this test's range

	// Pre-register YAML detector events in events.Core before starting Tracee
	// This is required for detector registration to succeed
	eventNameToID, err := detectors.CreateEventsFromDetectors(startID, result.Detectors)
	require.NoError(t, err, "Failed to create detector events")

	// Build list of all events to select: detector outputs + their input dependencies
	eventsToSelect := make([]events.ID, 0)

	// Add detector output events
	for _, eventID := range eventNameToID {
		eventsToSelect = append(eventsToSelect, eventID)
	}

	// Optionally add input events that detectors depend on. Skipped by the scoped variant so base
	// events carry only the detector's scoped dependency rule (no broad rule to union-defeat it).
	if selectInputs {
		inputEventNames := make(map[string]bool)
		for _, det := range result.Detectors {
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
			Detectors:      result.Detectors, // Only use YAML detectors for testing
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

// buildCommBinary writes a byte-for-byte copy of /usr/bin/true into dir under the given name and makes
// it executable, returning its path. Executing it yields a single-threaded process whose comm is that
// name (the exec'd file's basename, truncated to TASK_COMM_LEN-1 = 15 chars). Tests use unique, unusual
// comms so a scope filter matches exactly the processes the test spawns and nothing else on the host.
func buildCommBinary(t *testing.T, dir, comm string) string {
	return buildCommBinaryFrom(t, dir, comm, "/usr/bin/true")
}

// buildCommBinaryFrom is buildCommBinary with a chosen source binary, so a test can control the exit
// code (e.g. /usr/bin/true exits 0, /usr/bin/false exits 1) while keeping the same comm. Two binaries
// sharing a comm must live in different dirs (the comm is the file basename).
func buildCommBinaryFrom(t *testing.T, dir, comm, src string) string {
	t.Helper()
	srcBytes, err := os.ReadFile(src)
	require.NoError(t, err, "reading %s", src)
	p := filepath.Join(dir, comm)
	require.NoError(t, os.WriteFile(p, srcBytes, 0o755))
	return p
}

// countDetectorEvents counts buffered events with the given produced-event name.
func countDetectorEvents(buf *testutils.EventBuffer, eventName string) int {
	n := 0
	for _, e := range buf.GetCopy() {
		if e != nil && e.Name == eventName {
			n++
		}
	}
	return n
}

// waitForDetectorCount waits until at least want events named eventName are buffered (or timeout),
// returning the final count. Callers assert the exact expected value (a unique comm caps the count, so
// it can reach want but never exceed it).
func waitForDetectorCount(buf *testutils.EventBuffer, eventName string, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for countDetectorEvents(buf, eventName) < want && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	return countDetectorEvents(buf, eventName)
}

// scopeExitDetectorYAML is a detector requiring sched_process_exit scoped to a comm. Format args:
// id, produced-event name, comm. pid comes from the process context (always present), so a fired
// detection never depends on event data fields. sched_process_exit is used because it has no
// derivation (so a userland drop increments stats.EventsFiltered - the kernel-enforcement signal).
const scopeExitDetectorYAML = `type: detector
id: %s
produced_event:
  name: %s
  version: 1.0.0
  description: Scope-pushdown kernel-enforcement test detector
  tags:
    - test
  fields:
    - name: pid
      type: uint32

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exit
      dependency: required
      scope_filters:
        - comm=%s

auto_populate:
  detected_from: true

output:
  fields:
    - name: pid
      expression: workload.process.pid
`

// consumerDetectorYAML is a detector consuming another detector's output event (no scope of its own).
// Format args: id, produced-event name, input-event name. It re-emits the input's pid field, so a
// multi-level chain propagates the scope-filtered base event up through both levels.
const consumerDetectorYAML = `type: detector
id: %s
produced_event:
  name: %s
  version: 1.0.0
  description: Consumer detector for multi-level chain test
  tags:
    - test
  fields:
    - name: pid
      type: uint32

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: %s
      dependency: required

auto_populate:
  detected_from: true

output:
  fields:
    - name: pid
      expression: getEventData("pid")
`

// Test Cases

// Test_YAMLDetectorBasicLoading tests that YAML detectors are discovered and loaded correctly
func Test_YAMLDetectorBasicLoading(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Create a simple YAML detector
	detectorYAML := `type: detector
id: yaml-test-001
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
      expression: getEventData("pathname")
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
}

// Test_YAMLDetectorEventGeneration tests that a YAML detector produces events with correct field extraction
func Test_YAMLDetectorEventGeneration(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Create a detector that extracts multiple fields
	detectorYAML := `type: detector
id: yaml-test-002
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
      expression: getEventData("pathname")
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

	// Trigger the detector by executing /usr/bin/true
	cmd := exec.Command("/usr/bin/true")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/true")

	// Wait for the detector event
	evt := waitForDetectorEvent(buf, "test_event_generation", 5*time.Second)
	require.NotNil(t, evt, "Expected test_event_generation event not found")

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
}

// Test_YAMLDetectorChaining tests that YAML detectors can consume events from other YAML detectors
func Test_YAMLDetectorChaining(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Level 1: Base detector that detects exec of /usr/bin/id
	level1YAML := `type: detector
id: yaml-chain-level1
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
      expression: getEventData("pathname")
    - name: pid
      expression: workload.process.pid
`

	// Level 2: Composed detector that consumes level 1 output
	level2YAML := `type: detector
id: yaml-chain-level2
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
      expression: getEventData("binary_path")
    - name: original_pid
      expression: getEventData("pid")
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

	// Trigger the detector chain by executing /usr/bin/id
	cmd := exec.Command("/usr/bin/id")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/id")

	// Wait for both level 1 and level 2 events
	level1Evt := waitForDetectorEvent(buf, "test_exec_detected", 5*time.Second)
	require.NotNil(t, level1Evt, "Expected level 1 event test_exec_detected not found")

	level2Evt := waitForDetectorEvent(buf, "test_exec_enriched", 5*time.Second)
	require.NotNil(t, level2Evt, "Expected level 2 event test_exec_enriched not found")

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
}

// Test_YAMLDetectorFilters tests that data_filters and scope_filters work correctly
func Test_YAMLDetectorFilters(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Create a detector with specific pathname filter
	detectorYAML := `type: detector
id: yaml-test-filters
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
        - pathname=/usr/bin/true

auto_populate:
  detected_from: true

output:
  fields:
    - name: matched_path
      expression: getEventData("pathname")
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

	// Clear buffer before tests
	buf.Clear()

	// Test 1: Execute matching pathname - should fire
	cmd := exec.Command("/usr/bin/true")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /usr/bin/true")

	time.Sleep(1 * time.Second)

	matchedEvt := waitForDetectorEvent(buf, "test_filter_match", 3*time.Second)
	assert.NotNil(t, matchedEvt, "Detector should fire for matching pathname /usr/bin/true")

	if matchedEvt != nil {
		matchedPath := getArgValue(matchedEvt, "matched_path")
		assert.Contains(t, matchedPath, "/usr/bin/true", "matched_path should contain /usr/bin/true")
	}

	// Wait for any remaining events from test 1 to arrive before clearing
	time.Sleep(200 * time.Millisecond)

	// Clear buffer for next test
	buf.Clear()

	// Test 2: Execute non-matching pathname - should NOT fire
	cmd = exec.Command("/usr/bin/false")
	_ = cmd.Run() // /usr/bin/false exits with code 1 by design, ignore error

	time.Sleep(1 * time.Second)

	unmatchedEvt := waitForDetectorEvent(buf, "test_filter_match", 2*time.Second)
	assert.Nil(t, unmatchedEvt, "Detector should NOT fire for non-matching pathname /usr/bin/false")
}

// Test_YAMLDetectorScopeFilterPushdown is the scope-filter counterpart of Test_YAMLDetectorFilters and
// the integration counterpart of the Phase 2 scope pushdown: a detector declaring scope_filters on a
// base event fires only for the workload matching that scope. It exercises the full scope path
// (registry -> PolicyManager provider -> RecomputeRules -> DetectorScopeFilter -> kernel comm filter +
// userland matchPolicies), proving the pushed-down filter narrows the base event correctly end-to-end.
func Test_YAMLDetectorScopeFilterPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	yamlDir := t.TempDir()

	// Detector subscribes to sched_process_exec with a comm scope filter (workload-level).
	detectorYAML := `type: detector
id: yaml-test-scope-filters
produced_event:
  name: test_scope_filter_match
  version: 1.0.0
  description: Test detector for scope filter pushdown (Phase 2)
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
      scope_filters:
        - comm=true

auto_populate:
  detected_from: true

output:
  fields:
    - name: matched_path
      expression: getEventData("pathname")
`

	createTempYAMLDetector(t, yamlDir, "test_scope_filters.yaml", detectorYAML)

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

	buf.Clear()

	// Matching comm (/usr/bin/true -> comm "true") must fire the detector.
	require.NoError(t, exec.Command("/usr/bin/true").Run(), "Failed to execute /usr/bin/true")
	time.Sleep(1 * time.Second)

	matchedEvt := waitForDetectorEvent(buf, "test_scope_filter_match", 3*time.Second)
	assert.NotNil(t, matchedEvt, "Detector should fire for a process matching scope comm=true")

	// Wait for any remaining events to arrive before clearing.
	time.Sleep(200 * time.Millisecond)
	buf.Clear()

	// Non-matching comm (/usr/bin/false -> comm "false") must NOT fire the detector.
	_ = exec.Command("/usr/bin/false").Run() // /usr/bin/false exits 1 by design, ignore error
	time.Sleep(1 * time.Second)

	unmatchedEvt := waitForDetectorEvent(buf, "test_scope_filter_match", 2*time.Second)
	assert.Nil(t, unmatchedEvt, "Detector should NOT fire for a process not matching scope comm=true")
}

// Test_YAMLDetectorScopeFilterKernelPushdown proves the detector-declared scope filter is enforced
// IN THE KERNEL, not merely re-checked in userland - the substantive Phase 2 claim. Its companion
// Test_YAMLDetectorScopeFilterPushdown only proves the filter WORKS end-to-end (a kernel drop and a
// userland drop look identical from the output stream); this test proves WHERE the drop happens, with
// deterministic exact counts.
//
// Design (deterministic, self-contained workload):
//   - The scoped comm is a UNIQUE, unusual string (derived from this test process's pid), and the
//     matching processes are copies of /usr/bin/true renamed to that comm. So the ONLY processes on the
//     whole system that can match the filter are the ones this test spawns - no reliance on ambient
//     activity or fuzzy thresholds.
//   - In the kernel (tracee.bpf.c sched_process_exit) a non-matching exit hits
//     `evaluate_scope_filters` -> `if (!rules_matched) return 0;` and is dropped BEFORE
//     events_perf_submit: it never enters the perf buffer, never reaches userland. So:
//       * matching exits: kernel submits exactly one per single-threaded process -> the pipeline sees
//         exactly matchRuns of them -> the detector fires exactly matchRuns times (no loss, because
//         non-matching events never even occupy the buffer);
//       * non-matching exits (our nonMatchRuns copies + every background process exit): dropped in the
//         kernel -> stats.EventsFiltered (events the kernel SUBMITTED but userland then dropped) stays
//         at exactly 0. If the filter lived only in userland, the kernel would submit them all and this
//         counter would climb.
//
// sched_process_exit is the base event because (a) it has NO derivation, so a userland drop actually
// increments EventsFiltered (events WITH a derivation take the keep-for-derivation branch and bypass
// that counter - which is why sched_process_exec, used by the companion test, cannot serve here), and
// (b) the harness forces Source=SourceNone (no process tree), so nothing else selects it with a broad
// rule that would union-defeat the kernel filter. Detector outputs never touch EventsFiltered
// (matchPoliciesProto just skips), so the counter isolates the base event.
func Test_YAMLDetectorScopeFilterKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	// Unique, unusual comms: nothing else on the system shares them, so the matching set is exactly the
	// processes this test spawns.
	matchComm := fmt.Sprintf("trcok%d", os.Getpid()) // e.g. "trcok1234567" (<= 12 chars)
	otherComm := fmt.Sprintf("trcno%d", os.Getpid())

	// Two single-threaded executables (byte-for-byte copies of /usr/bin/true) named by those comms.
	binDir := t.TempDir()
	matchBin := buildCommBinary(t, binDir, matchComm)
	otherBin := buildCommBinary(t, binDir, otherComm)

	yamlDir := t.TempDir()
	createTempYAMLDetector(t, yamlDir, "test_scope_kernel_pushdown.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-test-scope-kernel-pushdown", "test_scope_kernel_pushdown", matchComm))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectorsScoped(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	// Let the comm filter map get programmed before measuring, then start from a clean slate.
	time.Sleep(2 * time.Second)
	buf.Clear()

	const (
		matchRuns    = 20
		nonMatchRuns = 200
	)

	baseline := trc.Stats().EventsFiltered.Get()

	// Controlled NON-matching workload: comm never equals the scoped comm. The kernel must drop every
	// one before submission, so none of these can ever reach userland.
	for i := 0; i < nonMatchRuns; i++ {
		_ = exec.Command(otherBin).Run()
	}

	// Controlled MATCHING workload: each single-threaded exit is submitted once and fires the detector.
	for i := 0; i < matchRuns; i++ {
		require.NoError(t, exec.Command(matchBin).Run())
	}

	// Tit for tat on the matching side: matchRuns unique-comm exits in -> exactly matchRuns detections
	// out (one per single-threaded process; no loss, since non-matching events never occupied the buffer).
	got := waitForDetectorCount(buf, "test_scope_kernel_pushdown", matchRuns, 10*time.Second)
	require.Equal(t, matchRuns, got, "expected exactly one detection per matching exit")

	// Kernel enforcement, deterministic: every non-matching exit (our nonMatchRuns plus all background
	// process exits during the window) was dropped in the kernel, so none reached userland to be
	// filtered. Any non-zero value here means non-matching sched_process_exit events were submitted -
	// i.e. the detector scope comm=<unique> was NOT enforced in the kernel.
	filteredDelta := trc.Stats().EventsFiltered.Get() - baseline
	require.Zero(t, filteredDelta,
		"EventsFiltered moved by %d: non-matching sched_process_exit events reached userland, so the "+
			"detector scope comm=%s was NOT enforced in the kernel", filteredDelta, matchComm)
}

// Test_YAMLDetectorScopeFilterUnionKernelPushdown proves how the kernel filter behaves when TWO
// detectors subscribe to the SAME base event (sched_process_exit) with DISTINCT comm scopes. The
// kernel comm filter for the event becomes the UNION of both scopes, so:
//   - a process matching EITHER comm is submitted (union widening never drops an event some rule wants);
//   - a process matching NEITHER is still dropped in the kernel (the union is {A,B}, not "everything");
//   - each detector fires only for ITS OWN comm - the dispatcher applies each subscription's own scope
//     filter (dispatch.go), so an A-process never fires detector B even though the union submitted it.
//
// Determinism comes from three unique comms (A, B, and a complement matching neither). Exact counts:
// detector A fires exactly runsA times, detector B exactly runsB, and EventsFiltered stays 0 (every
// complement exit, plus all background exits, is dropped in the kernel; A/B exits each match their own
// rule in userland so they are never userland-filtered).
func Test_YAMLDetectorScopeFilterUnionKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trcua%d", os.Getpid())
	commB := fmt.Sprintf("trcub%d", os.Getpid())
	commNone := fmt.Sprintf("trcun%d", os.Getpid()) // matches neither scope

	binDir := t.TempDir()
	binA := buildCommBinary(t, binDir, commA)
	binB := buildCommBinary(t, binDir, commB)
	binNone := buildCommBinary(t, binDir, commNone)

	yamlDir := t.TempDir()
	createTempYAMLDetector(t, yamlDir, "union_a.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-union-a", "test_union_a", commA))
	createTempYAMLDetector(t, yamlDir, "union_b.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-union-b", "test_union_b", commB))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectorsScoped(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	const (
		runsA    = 15
		runsB    = 15
		runsNone = 100
	)

	baseline := trc.Stats().EventsFiltered.Get()

	// Complement (matches neither scope) - the kernel must drop all of these.
	for i := 0; i < runsNone; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	// Each half of the union.
	for i := 0; i < runsA; i++ {
		require.NoError(t, exec.Command(binA).Run())
	}
	for i := 0; i < runsB; i++ {
		require.NoError(t, exec.Command(binB).Run())
	}

	gotA := waitForDetectorCount(buf, "test_union_a", runsA, 10*time.Second)
	gotB := waitForDetectorCount(buf, "test_union_b", runsB, 10*time.Second)

	// Both halves of the union are submitted and attributed to the correct detector (unique comms cap
	// each count, so exact equality also proves no cross-firing: A never fired for a B or complement exit).
	require.Equal(t, runsA, gotA, "detector A must fire once per commA exit (union half A submitted)")
	require.Equal(t, runsB, gotB, "detector B must fire once per commB exit (union half B submitted)")

	// The complement was dropped in the kernel (never reached userland), and A/B exits each matched their
	// own rule so were not userland-filtered. A non-zero value means the union kernel filter failed to
	// drop the complement (or dropped a needed event that userland then had to reconsider).
	filteredDelta := trc.Stats().EventsFiltered.Get() - baseline
	require.Zero(t, filteredDelta,
		"EventsFiltered moved by %d: the union comm filter {%s,%s} did not cleanly gate submission in the kernel",
		filteredDelta, commA, commB)
}

// Test_YAMLDetectorMultiLevelScopeKernelPushdown proves scope pushdown on a base event holds across a
// TWO-LEVEL detector chain. Level 1 scopes sched_process_exit to a unique comm and emits E1; level 2
// consumes E1 (no scope of its own) and emits E2. The scope filter is declared on level 1's base event,
// but level 2 is the top consumer - so this exercises the matched-rules chain mapping (the base event's
// scope is threaded onto the transitive dependency rule) together with kernel enforcement.
//
// Deterministic: a unique matching comm fires the whole chain exactly runs times at BOTH levels; a
// complement comm fires neither and is dropped in the kernel, so EventsFiltered stays 0.
func Test_YAMLDetectorMultiLevelScopeKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commX := fmt.Sprintf("trcml%d", os.Getpid())
	commNone := fmt.Sprintf("trcmn%d", os.Getpid())

	binDir := t.TempDir()
	binX := buildCommBinary(t, binDir, commX)
	binNone := buildCommBinary(t, binDir, commNone)

	yamlDir := t.TempDir()
	// Level 1: sched_process_exit scoped to commX -> test_ml_level1.
	createTempYAMLDetector(t, yamlDir, "ml_level1.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-ml-level1", "test_ml_level1", commX))
	// Level 2: consumes test_ml_level1 -> test_ml_level2.
	createTempYAMLDetector(t, yamlDir, "ml_level2.yaml",
		fmt.Sprintf(consumerDetectorYAML, "yaml-ml-level2", "test_ml_level2", "test_ml_level1"))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectorsScoped(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	const (
		runs     = 15
		runsNone = 100
	)

	baseline := trc.Stats().EventsFiltered.Get()

	// Complement: dropped in the kernel, so it can fire neither level.
	for i := 0; i < runsNone; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	// Matching: drives the full chain.
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binX).Run())
	}

	gotL1 := waitForDetectorCount(buf, "test_ml_level1", runs, 10*time.Second)
	gotL2 := waitForDetectorCount(buf, "test_ml_level2", runs, 10*time.Second)

	// The scope-filtered base event drives BOTH levels exactly once per matching process.
	require.Equal(t, runs, gotL1, "level 1 must fire once per matching exit")
	require.Equal(t, runs, gotL2, "level 2 must fire once per level-1 event (chain propagated)")

	// Complement exits were dropped in the kernel; matching exits matched the chain's base rule in
	// userland. Non-zero means the scope pushed onto the transitive base dependency did not gate the
	// kernel submission.
	filteredDelta := trc.Stats().EventsFiltered.Get() - baseline
	require.Zero(t, filteredDelta,
		"EventsFiltered moved by %d: the base scope comm=%s was not enforced in the kernel across the chain",
		filteredDelta, commX)
}

// Test_YAMLDetectorFiveLevelScopeKernelPushdown drives the MAXIMUM supported detector chain:
// base -> L1 -> L2 -> L3 -> L4 -> L5 (five detectors). The bound is addTransitiveDependencyRules
// (policy_manager.go), whose recursion reaches the base event at depth == number of detector levels and
// errors when depth > maxDepth (5). So the top consumer L5 reaches the base at depth 5 (allowed); a sixth
// level would reach the base at depth 6 and fail rule computation at init. The dispatch loop cap
// (maxDetectorChainDepth=5) is looser and has room to spare. Only L1 declares a scope (comm on
// sched_process_exit); it must thread down the whole transitive chain so the kernel still drops the
// complement. A matching comm drives all five levels exactly `runs` times; a complement comm fires none
// and is dropped in the kernel (EventsFiltered stays 0).
func Test_YAMLDetectorFiveLevelScopeKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commX := fmt.Sprintf("trcm5%d", os.Getpid())
	commNone := fmt.Sprintf("trcn5%d", os.Getpid())

	binDir := t.TempDir()
	binX := buildCommBinary(t, binDir, commX)
	binNone := buildCommBinary(t, binDir, commNone)

	yamlDir := t.TempDir()
	// L1 scopes the base event; L2..L5 each consume the previous level's output (no scope of their own).
	createTempYAMLDetector(t, yamlDir, "ml5_level1.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-ml5-level1", "test_ml5_level1", commX))
	createTempYAMLDetector(t, yamlDir, "ml5_level2.yaml",
		fmt.Sprintf(consumerDetectorYAML, "yaml-ml5-level2", "test_ml5_level2", "test_ml5_level1"))
	createTempYAMLDetector(t, yamlDir, "ml5_level3.yaml",
		fmt.Sprintf(consumerDetectorYAML, "yaml-ml5-level3", "test_ml5_level3", "test_ml5_level2"))
	createTempYAMLDetector(t, yamlDir, "ml5_level4.yaml",
		fmt.Sprintf(consumerDetectorYAML, "yaml-ml5-level4", "test_ml5_level4", "test_ml5_level3"))
	createTempYAMLDetector(t, yamlDir, "ml5_level5.yaml",
		fmt.Sprintf(consumerDetectorYAML, "yaml-ml5-level5", "test_ml5_level5", "test_ml5_level4"))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectorsScoped(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	const (
		runs     = 15
		runsNone = 100
	)

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < runsNone; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binX).Run())
	}

	// Every level fires exactly once per matching process - the chain propagates end to end.
	for lvl, name := range []string{"test_ml5_level1", "test_ml5_level2", "test_ml5_level3", "test_ml5_level4", "test_ml5_level5"} {
		got := waitForDetectorCount(buf, name, runs, 15*time.Second)
		require.Equal(t, runs, got, "level %d (%s) must fire once per matching exit", lvl+1, name)
	}

	// The base scope comm=commX, threaded onto the transitive dependency five hops down, gated the kernel
	// submission: the complement never reached userland.
	filteredDelta := trc.Stats().EventsFiltered.Get() - baseline
	require.Zero(t, filteredDelta,
		"EventsFiltered moved by %d: base scope comm=%s was not enforced in the kernel across the 5-level chain",
		filteredDelta, commX)
}

// Test_YAMLDetectorErrorHandling tests graceful handling of invalid YAML and missing fields
func Test_YAMLDetectorErrorHandling(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	// Suppress logger output for expected warnings during error handling tests
	teardown := testutils.EnableTestLogger(t, logger.ErrorLevel)
	defer teardown()

	yamlDir := t.TempDir()

	// Test 1: Invalid YAML syntax - should be logged but not crash
	invalidYAML := `type: detector
id: yaml-invalid
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
	validYAML := `type: detector
id: yaml-test-valid
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
      expression: getEventData("pathname")
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
      expression: getEventData("nonexistent_field")
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

	// Trigger the detector
	cmd := exec.Command("/bin/hostname")
	err := cmd.Run()
	require.NoError(t, err, "Failed to execute /bin/hostname")

	time.Sleep(1 * time.Second)

	// The detector should NOT produce an event because required field is missing
	evt := waitForDetectorEvent(buf, "test_required_field", 2*time.Second)
	assert.Nil(t, evt, "Detector should skip detection when required field is missing")
}
