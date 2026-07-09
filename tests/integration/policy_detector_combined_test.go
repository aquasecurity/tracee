package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// startTraceeWithDetectorsAndPolicies starts Tracee with YAML detectors AND extra plain policies. The
// detector OUTPUT events are selected (outputs-only, so a detector's base scope is not defeated by the
// harness itself), and the extra policies are merged in - which is exactly how a real deployment mixes
// detectors with user policies on the same base events. Used by the mixed policy+detector scenarios.
func startTraceeWithDetectorsAndPolicies(ctx context.Context, t *testing.T, yamlDir string, extra []*policy.Policy) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	t.Helper()

	result := yamldetectors.LoadFromDirectories([]string{yamlDir})

	startID := events.ID(nextDetectorEventID.Add(uint32(len(result.Detectors))))
	startID -= events.ID(len(result.Detectors))
	eventNameToID, err := detectors.CreateEventsFromDetectors(startID, result.Detectors)
	require.NoError(t, err, "Failed to create detector events")

	// Select ONLY detector outputs (each output pulls its base events in as scoped dependencies).
	outputs := make([]events.ID, 0, len(eventNameToID))
	for _, id := range eventNameToID {
		outputs = append(outputs, id)
	}
	policies := testutils.BuildPoliciesFromEvents(outputs)

	initial := make([]interface{}, 0, len(policies)+len(extra))
	for _, p := range policies {
		initial = append(initial, p)
	}
	for _, p := range extra {
		initial = append(initial, p)
	}

	cfg := config.Config{
		Capabilities:    &config.CapabilitiesConfig{BypassCaps: true},
		InitialPolicies: initial,
		DetectorConfig: config.DetectorConfig{
			Detectors:      result.Detectors,
			YAMLSearchDirs: []string{yamlDir},
		},
	}

	trc, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	stream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)

	require.NoError(t, testutils.WaitForTraceeStart(trc), "Tracee failed to start")

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

// Test_PolicyBroadDefeatsDetectorScope (scenario C1): a detector scopes sched_process_exit to commX,
// while a BROAD policy (no scope) selects the same base event. The unscoped policy rule union-defeats the
// detector's kernel comm filter, so the kernel must submit EVERY exit - yet the detector stays correct,
// firing only for commX because the dispatcher applies each detector's own scope filter (dispatch.go).
//
// The proof is behavioral (S5): the COMPLEMENT base events (which the scoped-only detector tests showed
// are dropped in the kernel) now appear in the stream, attributed to the broad policy - direct evidence
// the kernel over-submitted. Meanwhile the detector output fires exactly once per commX exit and never
// for the complement.
func Test_PolicyBroadDefeatsDetectorScope(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commX := fmt.Sprintf("trcc1x%d", os.Getpid())    // detector scope matches this
	commNone := fmt.Sprintf("trcc1n%d", os.Getpid()) // detector rejects; broad policy accepts

	binX := buildCommBinary(t, t.TempDir(), commX)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	yamlDir := t.TempDir()
	createTempYAMLDetector(t, yamlDir, "c1.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-c1", "test_c1", commX))

	// Broad policy on the SAME base event (sched_process_exit), no scope -> forces submission of all exits.
	broad := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-broad", ""),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithDetectorsAndPolicies(ctx, t, yamlDir, broad)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	const runs = 15

	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binNone).Run()) // complement (detector rejects)
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binX).Run()) // detector-matching
	}

	// The detector fires exactly once per commX exit and never for the complement, even though the base
	// event is now broadly submitted (per-detector dispatch scope keeps it correct).
	gotDet := waitForDetectorCount(buf, "test_c1", runs, 10*time.Second)
	require.Equal(t, runs, gotDet, "detector must fire once per commX exit and not for the complement")

	// The broad policy defeated the kernel scope: complement base events were submitted and emitted,
	// attributed to the broad policy. Under the scoped-only detector tests these are dropped in the kernel.
	matchedNone, noneCount := exitPoliciesForComm(buf, commNone)
	require.Positive(t, noneCount,
		"complement base events must be emitted via the broad policy (kernel over-submitted)")
	require.Equal(t, []string{"pol-broad"}, matchedNone,
		"complement base events attributed to the broad policy only")

	// commX base events are likewise emitted via the broad policy.
	_, xCount := exitPoliciesForComm(buf, commX)
	require.Positive(t, xCount, "commX base events must be emitted via the broad policy")
}

// Test_PolicyAndDetectorSameScope (scenario C3): a detector and a policy scope the SAME comm on the same
// base event. The kernel scope stays comm=A (the two identical scopes collapse); the detector fires for
// commA and the policy emits the commA base event attributed to itself; the complement is dropped in the
// kernel.
func Test_PolicyAndDetectorSameScope(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trcc3a%d", os.Getpid())
	commNone := fmt.Sprintf("trcc3n%d", os.Getpid())

	binA := buildCommBinary(t, t.TempDir(), commA)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	yamlDir := t.TempDir()
	createTempYAMLDetector(t, yamlDir, "c3.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-c3", "test_c3", commA))

	pol := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-a", commA),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithDetectorsAndPolicies(ctx, t, yamlDir, pol)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	const runs = 15

	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binNone).Run()) // complement
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binA).Run()) // matches both detector and policy
	}

	gotDet := waitForDetectorCount(buf, "test_c3", runs, 10*time.Second)
	require.Equal(t, runs, gotDet, "detector fires once per commA exit")

	mA, aCount := exitPoliciesForComm(buf, commA)
	require.Positive(t, aCount, "commA base event must be emitted via the policy")
	require.Contains(t, mA, "pol-a", "commA base event attributed to pol-a")

	_, none := exitPoliciesForComm(buf, commNone)
	require.Zero(t, none, "complement must be dropped in the kernel (identical scopes collapse to comm=A)")
}

// Test_PolicyAndDetectorDifferentScope (scenario C2): a detector scopes commA while a policy scopes commB
// on the same base event. The kernel filter is the union {A,B}: the detector fires only for commA
// (per-detector dispatch scope), the policy emits commB base events attributed to itself, and the
// complement (neither comm) is dropped in the kernel.
func Test_PolicyAndDetectorDifferentScope(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trcc2a%d", os.Getpid())    // detector scope
	commB := fmt.Sprintf("trcc2b%d", os.Getpid())    // policy scope
	commNone := fmt.Sprintf("trcc2n%d", os.Getpid()) // neither

	binA := buildCommBinary(t, t.TempDir(), commA)
	binB := buildCommBinary(t, t.TempDir(), commB)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	yamlDir := t.TempDir()
	createTempYAMLDetector(t, yamlDir, "c2.yaml",
		fmt.Sprintf(scopeExitDetectorYAML, "yaml-c2", "test_c2", commA))

	pol := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-b", commB),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithDetectorsAndPolicies(ctx, t, yamlDir, pol)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	const runs = 15

	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binNone).Run()) // complement
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binB).Run()) // policy dimension
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binA).Run()) // detector dimension
	}

	// Detector fires only for commA (its dispatch scope), never for commB or the complement.
	gotDet := waitForDetectorCount(buf, "test_c2", runs, 10*time.Second)
	require.Equal(t, runs, gotDet, "detector fires once per commA exit only")

	// The policy emits the commB base events (its half of the kernel union).
	mB, bCount := exitPoliciesForComm(buf, commB)
	require.Positive(t, bCount, "commB base events must be emitted via the policy")
	require.Contains(t, mB, "pol-b", "commB base events attributed to pol-b")

	// The complement matched neither the detector's nor the policy's scope: dropped in the kernel.
	_, none := exitPoliciesForComm(buf, commNone)
	require.Zero(t, none, "complement must be dropped in the kernel (union is {A,B}, not everything)")
}
