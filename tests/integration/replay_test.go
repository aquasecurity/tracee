package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	traceecmd "github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// Test_ReplayCapturedEvents guards the live-output → replay-input contract
// end to end: events captured from a real tracee run through the production
// json printer (the `--output json:file` code path) must be replayable, and
// a YAML detector must fire on them.
func Test_ReplayCapturedEvents(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	capturePath := captureExecEventsToFile(t)

	// The json file printer buffers and flushes on Close, so the file is
	// only complete after the capture teardown above
	captured, err := os.ReadFile(capturePath)
	require.NoError(t, err)
	require.Contains(t, string(captured), "/usr/bin/true",
		"the captured exec event should be in the json file after printer close")

	// --- Replay phase: run the captured file through a YAML detector ---

	yamlDir := t.TempDir()
	detectorYAML := `type: detector
id: replay-test-001
produced_event:
  name: replay_exec_detected
  version: 1.0.0
  description: Replay integration test detector
  tags:
    - test
  fields:
    - name: exec_path
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required

conditions:
  - getEventData("pathname").endsWith("/true")

output:
  fields:
    - name: exec_path
      expression: getEventData("pathname")
`
	createTempYAMLDetector(t, yamlDir, "replay_exec.yaml", detectorYAML)

	result := yamldetectors.LoadFromDirectories([]string{yamlDir})
	require.Empty(t, result.Errors, "YAML detector should load cleanly")
	require.Len(t, result.Detectors, 1)

	// Register the detector event in the global events.Core registry, using
	// the shared allocator to avoid ID conflicts with other tests
	startID := events.ID(nextDetectorEventID.Add(uint32(len(result.Detectors))))
	startID -= events.ID(len(result.Detectors))
	_, err = detectors.CreateEventsFromDetectors(startID, result.Detectors)
	require.NoError(t, err, "Failed to create detector events")

	replayOutPath := filepath.Join(t.TempDir(), "replay_out.json")
	replayDest, err := flags.PreparePrinterConfig("json", replayOutPath)
	require.NoError(t, err)

	runner := traceecmd.ReplayRunner{
		TraceeConfig: config.Config{
			DetectorConfig: config.DetectorConfig{
				Detectors:      result.Detectors,
				YAMLSearchDirs: []string{yamlDir},
			},
			Output: &config.OutputConfig{
				Streams: []config.Stream{
					{Destinations: []config.Destination{replayDest}},
				},
			},
		},
		ReplayPath: capturePath,
	}
	require.NoError(t, runner.Run(context.Background()), "Replay runner failed")

	// The detector must have fired on the captured exec event
	replayOut, err := os.ReadFile(replayOutPath)
	require.NoError(t, err)
	assert.Contains(t, string(replayOut), "replay_exec_detected",
		"the YAML detector should fire on the replayed captured event")
	assert.Contains(t, string(replayOut), "/usr/bin/true",
		"the detector output should carry the extracted exec path")
}

// captureExecEventsToFile runs a live tracee capturing sched_process_exec
// events to a JSON Lines file through the production json printer (the
// `--output json:events.json` code path), triggers /usr/bin/true until the
// event is observed, and tears everything down (deferred, so it also runs on
// failure). The returned file is complete once this helper returns: the json
// file printer buffers output and only guarantees a flush on Close, which is
// also why the trigger is detected through a second in-memory stream rather
// than by polling the file.
func captureExecEventsToFile(t *testing.T) string {
	t.Helper()

	capturePath := filepath.Join(t.TempDir(), "events.json")

	execEventID, ok := events.Core.GetDefinitionIDByName("sched_process_exec")
	require.True(t, ok, "sched_process_exec should be a known event")

	policies := testutils.BuildPoliciesFromEvents([]events.ID{execEventID})
	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}

	cfg := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		InitialPolicies: initialPolicies,
	}

	ctx, cancel := context.WithCancel(context.Background())

	trc, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	if err != nil {
		cancel()
		require.NoError(t, err, "Failed to start Tracee")
	}

	// Deferred teardown, registered in reverse execution order; it runs on
	// both success and failure (require triggers the deferred unwind), so a
	// failed wait cannot leave goroutines behind for goleak to panic on
	defer func() {
		if waitErr := testutils.WaitForTraceeStop(trc); waitErr != nil {
			t.Logf("Tracee did not stop cleanly: %v", waitErr)
		}
	}()
	defer cancel() // stops tracee and the watch collector

	// printStream feeds the json printer; watchStream feeds an in-memory
	// buffer used to detect that the trigger was captured
	printStream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)

	watchStream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)
	defer trc.Unsubscribe(watchStream)

	require.NoError(t, testutils.WaitForTraceeStart(trc), "Tracee failed to start")

	captureDest, err := flags.PreparePrinterConfig("json", capturePath)
	require.NoError(t, err)
	capturePrinter, err := printer.New([]config.Destination{captureDest})
	require.NoError(t, err)
	defer capturePrinter.Close() // flushes the buffered json output

	printerDone := make(chan struct{})
	go func() {
		defer close(printerDone)
		capturePrinter.FromStream(printStream) // returns when the stream closes
	}()
	// LIFO: unsubscribing the print stream closes it, FromStream drains the
	// queued events and returns, then the wait below unblocks — only after
	// that does the deferred Close above flush the completed file
	defer func() { <-printerDone }()
	defer trc.Unsubscribe(printStream)

	buf := testutils.NewEventBuffer()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-watchStream.ReceiveEvents():
				if evt != nil {
					buf.AddEvent(evt)
				}
			}
		}
	}()

	// Trigger sched_process_exec until it is observed on the watch stream;
	// re-triggering each poll tolerates a lost first event
	require.Eventually(t, func() bool {
		_ = exec.Command("/usr/bin/true").Run()
		for _, evt := range buf.GetCopy() {
			if evt.Name == "sched_process_exec" && getArgValue(evt, "pathname") == "/usr/bin/true" {
				return true
			}
		}
		return false
	}, 15*time.Second, 200*time.Millisecond, "the triggered exec event should be captured")

	// Both streams were subscribed before the trigger, so once the watch
	// stream saw the event it was also queued to the print stream; the
	// deferred Unsubscribe closes the stream after queued events are
	// delivered, FromStream drains it, and Close flushes the file
	return capturePath
}

// Test_ReplayCLI drives the built tracee binary's replay subcommand as a
// user would, without needing root or eBPF: replay is pure userspace.
// Requires the binary at dist/tracee (skips otherwise).
func Test_ReplayCLI(t *testing.T) {
	if _, err := os.Stat(testutils.TraceeBinary); err != nil {
		t.Skipf("tracee binary not found at %s, build it first", testutils.TraceeBinary)
	}

	workDir := t.TempDir()

	detectorYAML := `type: detector
id: replay-cli-001
produced_event:
  name: cli_replay_detected
  version: 1.0.0
  description: Replay CLI test detector
  fields:
    - name: exec_path
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required

conditions:
  - getEventData("pathname") == "/bin/bash"

output:
  fields:
    - name: exec_path
      expression: getEventData("pathname")
`
	detectorPath := filepath.Join(workDir, "detector.yaml")
	require.NoError(t, os.WriteFile(detectorPath, []byte(detectorYAML), 0o644))

	// sched_process_exec is protobuf EventId 1015; replay dispatches by id
	eventsPath := filepath.Join(workDir, "events.json")
	eventsContent := `{"timestamp":"2026-01-01T00:00:00Z","id":1015,"name":"sched_process_exec","data":[{"name":"pathname","str":"/bin/bash"}]}
{"timestamp":"2026-01-01T00:00:01Z","id":1015,"name":"sched_process_exec","data":[{"name":"pathname","str":"/usr/bin/ls"}]}
`
	require.NoError(t, os.WriteFile(eventsPath, []byte(eventsContent), 0o644))

	t.Run("detector fires on matching event only", func(t *testing.T) {
		out, err := exec.Command(testutils.TraceeBinary,
			"replay", eventsPath, "--detectors", detectorPath).Output()
		require.NoError(t, err, "replay should succeed")

		require.Contains(t, string(out), "cli_replay_detected",
			"detector should fire on the matching event")
		assert.Contains(t, string(out), "/bin/bash")
		assert.Equal(t, 1, strings.Count(string(out), "cli_replay_detected"),
			"detector should fire exactly once (not on /usr/bin/ls)")
	})

	t.Run("oversized line fails the replay", func(t *testing.T) {
		oversizedPath := filepath.Join(workDir, "oversized.json")
		line := `{"id":1015,"name":"` + strings.Repeat("A", 17*1024*1024) + `"}`
		require.NoError(t, os.WriteFile(oversizedPath, []byte(line+"\n"), 0o644))

		out, err := exec.Command(testutils.TraceeBinary,
			"replay", oversizedPath, "--detectors", detectorPath).CombinedOutput()
		require.Error(t, err, "replay of an unreadable file must not exit 0")
		assert.Contains(t, string(out), "token too long")
	})

	t.Run("multiple output destinations are rejected", func(t *testing.T) {
		outFile := filepath.Join(workDir, "out.json")
		out, err := exec.Command(testutils.TraceeBinary,
			"replay", eventsPath, "--detectors", detectorPath,
			"--output", "json:"+outFile, "--output", "table").CombinedOutput()
		require.Error(t, err, "multiple destinations must be rejected")
		assert.Contains(t, string(out), "single output destination")
	})
}
