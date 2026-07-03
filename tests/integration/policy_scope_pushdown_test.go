package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	polv1beta1 "github.com/aquasecurity/tracee/pkg/policy/v1beta1"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// These tests cover the PLAIN-POLICY path of the matched-rules model on a common event (no detectors),
// the counterpart to the detector kernel-pushdown tests. They use the same deterministic recipe (unique,
// unusual comms via copies of /usr/bin/true, self-generated complement workloads) but add a signal the
// detector tests cannot show: because a policy-selected common event IS emitted, each event carries its
// matched-policy set (evt.Policies.Matched), so attribution is asserted exactly.
//
// Base event: sched_process_exit (no derivation, so EventsFiltered is a valid kernel-vs-userland signal,
// and it IS emitted so attribution is observable). See docs/matched-rules-test-scenarios.md (group A).

const schedProcessExitName = "sched_process_exit"

// exitScopePolicy builds a policy selecting sched_process_exit with an optional comm scope (empty comm =
// no scope, i.e. a broad rule that matches every workload) and optional per-event data/retval filters
// (e.g. "data.exit_code=0").
func exitScopePolicy(id int, name, comm string, ruleFilters ...string) testutils.PolicyFileWithID {
	scope := []string{}
	if comm != "" {
		scope = append(scope, "comm="+comm)
	}
	if ruleFilters == nil {
		ruleFilters = []string{}
	}
	return testutils.PolicyFileWithID{
		Id: id,
		PolicyFile: polv1beta1.PolicyFile{
			Metadata: polv1beta1.Metadata{Name: name},
			Spec: k8s.PolicySpec{
				Scope:          scope,
				DefaultActions: []string{"log"},
				Rules:          []k8s.Rule{{Event: schedProcessExitName, Filters: ruleFilters}},
			},
		},
	}
}

// startTraceeWithPolicies starts Tracee with the given policies (no detectors), subscribes, and returns
// the running instance, an event buffer, and the stream.
func startTraceeWithPolicies(ctx context.Context, t *testing.T, policies []*policy.Policy) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	t.Helper()

	cfg := config.Config{
		Capabilities:      &config.CapabilitiesConfig{BypassCaps: true},
		EnrichmentEnabled: false,
	}
	initial := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initial = append(initial, p)
	}
	cfg.InitialPolicies = initial

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
			case e := <-stream.ReceiveEvents():
				if e != nil {
					buf.AddEvent(e)
				}
			}
		}
	}()

	return trc, buf, stream
}

// exitPoliciesForComm returns the matched-policy set (sorted) of the first emitted sched_process_exit
// event whose process comm equals comm, along with the count of such events.
func exitPoliciesForComm(buf *testutils.EventBuffer, comm string) (matched []string, count int) {
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != schedProcessExitName {
			continue
		}
		if e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
			e.Workload.Process.Thread.Name != comm {
			continue
		}
		count++
		if matched == nil && e.Policies != nil {
			matched = append([]string(nil), e.Policies.Matched...)
			sort.Strings(matched)
		}
	}
	return matched, count
}

// waitForExitComm waits until at least want sched_process_exit events with the given comm are buffered
// (or timeout), returning the final count.
func waitForExitComm(buf *testutils.EventBuffer, comm string, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		if _, n := exitPoliciesForComm(buf, comm); n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Test_PolicyScopeSingleKernelPushdown (scenario A2): one policy scoping sched_process_exit to a unique
// comm. Matching exits are emitted attributed to that policy; the complement is dropped in the kernel
// (never emitted, EventsFiltered stays 0).
func Test_PolicyScopeSingleKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trca2m%d", os.Getpid())
	commNone := fmt.Sprintf("trca2n%d", os.Getpid())

	binDir := t.TempDir()
	binA := buildCommBinary(t, binDir, commA)
	binNone := buildCommBinary(t, binDir, commNone)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-a", commA),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithPolicies(ctx, t, policies)
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
		runsMatch = 15
		runsNone  = 100
	)

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < runsNone; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	for i := 0; i < runsMatch; i++ {
		require.NoError(t, exec.Command(binA).Run())
	}

	require.GreaterOrEqual(t, waitForExitComm(buf, commA, runsMatch, 10*time.Second), runsMatch,
		"matching exits must be emitted")

	matchedA, _ := exitPoliciesForComm(buf, commA)
	require.Equal(t, []string{"pol-a"}, matchedA, "matching exit must be attributed to pol-a only")

	_, noneCount := exitPoliciesForComm(buf, commNone)
	require.Zero(t, noneCount, "complement exits must be dropped in the kernel (not emitted)")

	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"EventsFiltered moved: complement sched_process_exit reached userland, so scope comm=%s was not kernel-enforced", commA)
}

// Test_PolicyScopeUnionKernelPushdown (scenario A4): two policies scoping sched_process_exit to DISTINCT
// comms. The kernel filter is the union {A,B}: A-exits attributed to pol-a, B-exits to pol-b, and the
// complement (matching neither) is still dropped in the kernel. Proves union widening plus exact
// per-policy attribution.
func Test_PolicyScopeUnionKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trc4a%d", os.Getpid())
	commB := fmt.Sprintf("trc4b%d", os.Getpid())
	commNone := fmt.Sprintf("trc4n%d", os.Getpid())

	binDir := t.TempDir()
	binA := buildCommBinary(t, binDir, commA)
	binB := buildCommBinary(t, binDir, commB)
	binNone := buildCommBinary(t, binDir, commNone)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-a", commA),
		exitScopePolicy(2, "pol-b", commB),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithPolicies(ctx, t, policies)
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
		runsMatch = 15
		runsNone  = 100
	)

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < runsNone; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	for i := 0; i < runsMatch; i++ {
		require.NoError(t, exec.Command(binA).Run())
	}
	for i := 0; i < runsMatch; i++ {
		require.NoError(t, exec.Command(binB).Run())
	}

	require.GreaterOrEqual(t, waitForExitComm(buf, commA, runsMatch, 10*time.Second), runsMatch)
	require.GreaterOrEqual(t, waitForExitComm(buf, commB, runsMatch, 10*time.Second), runsMatch)

	matchedA, _ := exitPoliciesForComm(buf, commA)
	matchedB, _ := exitPoliciesForComm(buf, commB)
	require.Equal(t, []string{"pol-a"}, matchedA, "A-exit attributed to pol-a only")
	require.Equal(t, []string{"pol-b"}, matchedB, "B-exit attributed to pol-b only")

	_, noneCount := exitPoliciesForComm(buf, commNone)
	require.Zero(t, noneCount, "complement (matches neither scope) must be dropped in the kernel")

	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"EventsFiltered moved: the union comm filter {%s,%s} did not cleanly gate submission in the kernel", commA, commB)
}

// Test_PolicyScopeUnionDefeatKernelPushdown (scenario A5): one scoped policy (comm=A) and one BROAD
// policy (no scope) on the same event. An unscoped rule defeats the kernel filter - the event must be
// submitted for every workload - yet matched-rules attribution stays correct: A-exits match both
// policies, complement exits match only the broad policy AND are emitted (proving the kernel over-
// submitted). EventsFiltered stays 0 because every submitted event matches at least the broad rule.
func Test_PolicyScopeUnionDefeatKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trc5a%d", os.Getpid())
	commNone := fmt.Sprintf("trc5n%d", os.Getpid())

	binDir := t.TempDir()
	binA := buildCommBinary(t, binDir, commA)
	binNone := buildCommBinary(t, binDir, commNone)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-a", commA),
		exitScopePolicy(2, "pol-broad", ""), // no scope -> matches every workload
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithPolicies(ctx, t, policies)
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
		runsMatch = 15
		runsNone  = 15
	)

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < runsNone; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	for i := 0; i < runsMatch; i++ {
		require.NoError(t, exec.Command(binA).Run())
	}

	require.GreaterOrEqual(t, waitForExitComm(buf, commA, runsMatch, 10*time.Second), runsMatch)
	// The broad policy causes the complement to be submitted too, so it appears in the stream.
	require.GreaterOrEqual(t, waitForExitComm(buf, commNone, runsNone, 10*time.Second), runsNone,
		"broad policy must cause the complement to be submitted (kernel filter defeated)")

	matchedA, _ := exitPoliciesForComm(buf, commA)
	matchedNone, _ := exitPoliciesForComm(buf, commNone)
	require.Equal(t, []string{"pol-a", "pol-broad"}, matchedA, "A-exit matches both the scoped and broad policy")
	require.Equal(t, []string{"pol-broad"}, matchedNone, "complement exit matches only the broad policy")

	// Every submitted event matched at least the broad rule, so nothing was userland-filtered.
	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"EventsFiltered moved unexpectedly: with a broad rule present every event should match a rule")
}

// exitEventsByCode returns the sorted matched-policy set of the first emitted sched_process_exit event
// with the given comm and exit_code, plus the count of such events.
func exitEventsByCode(buf *testutils.EventBuffer, comm string, code int32) (matched []string, count int) {
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != schedProcessExitName ||
			e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
			e.Workload.Process.Thread.Name != comm {
			continue
		}
		if v, ok := getArgValue(e, "exit_code").(int32); !ok || v != code {
			continue
		}
		count++
		if matched == nil && e.Policies != nil {
			matched = append([]string(nil), e.Policies.Matched...)
			sort.Strings(matched)
		}
	}
	return matched, count
}

// waitForExitCode waits until at least want sched_process_exit events with the given comm and exit_code
// are buffered (or timeout), returning the final count.
func waitForExitCode(buf *testutils.EventBuffer, comm string, code int32, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		if _, n := exitEventsByCode(buf, comm, code); n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Test_PolicyScopeKernelPlusDataUserland (scenario A6): a policy that combines a kernel-pushable scope
// (comm) with a data filter on a scalar field (exit_code). It proves split enforcement by ATTRIBUTION,
// using two policies on the same event:
//   - pol-data:   scope comm=A AND data.exit_code=0
//   - pol-nodata: scope comm=A only
//
// Both push comm to the kernel (union = {A}), so a comm complement is dropped in the kernel and never
// appears. For comm=A workloads:
//   - exit-0 (/usr/bin/true) matches BOTH policies         -> Policies == {pol-data, pol-nodata}
//   - exit-1 (/usr/bin/false) is SUBMITTED (comm matched), kept by pol-nodata, but excluded from pol-data
//     by the exit_code filter -> Policies == {pol-nodata} ONLY.
//
// The presence of exit-1 events attributed to pol-nodata is the key: it proves the kernel submitted them
// (so exit_code is NOT a kernel filter) and pol-data's exit_code filter dropped them in userland. If
// exit_code were kernel-enforced instead, exit-1 events would not appear at all and this test would fail
// loudly - which is exactly the ambiguity a single-policy EventsFiltered check could not resolve.
func Test_PolicyScopeKernelPlusDataUserland(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trc6a%d", os.Getpid())
	commNone := fmt.Sprintf("trc6n%d", os.Getpid())

	// Same comm, different exit codes -> different dirs (comm is the file basename).
	binExit0 := buildCommBinaryFrom(t, t.TempDir(), commA, "/usr/bin/true")   // comm=A, exit 0
	binExit1 := buildCommBinaryFrom(t, t.TempDir(), commA, "/usr/bin/false")  // comm=A, exit 1
	binNone := buildCommBinaryFrom(t, t.TempDir(), commNone, "/usr/bin/true") // comm complement

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-data", commA, "data.exit_code=0"),
		exitScopePolicy(2, "pol-nodata", commA),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithPolicies(ctx, t, policies)
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
		require.NoError(t, exec.Command(binNone).Run()) // comm complement -> kernel drop
	}
	for i := 0; i < runs; i++ {
		_ = exec.Command(binExit1).Run() // comm=A exit 1
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binExit0).Run()) // comm=A exit 0
	}

	require.GreaterOrEqual(t, waitForExitCode(buf, commA, 0, runs, 10*time.Second), runs,
		"exit-0 events must be emitted")

	m0, c0 := exitEventsByCode(buf, commA, 0)
	m1, c1 := exitEventsByCode(buf, commA, 1)
	_, cNone := exitPoliciesForComm(buf, commNone)
	t.Logf("A6 diagnostic: emitted commA exit0=%d%v exit1=%d%v; comm-complement emitted=%d", c0, m0, c1, m1, cNone)

	// exit-0 matches both policies (comm + exit_code both pass).
	require.Equal(t, []string{"pol-data", "pol-nodata"}, m0,
		"exit-0 events must match both policies")

	// exit-1 is submitted (kernel comm filter passed it) and kept by pol-nodata, proving exit_code is
	// enforced in USERLAND (not the kernel): if it were a kernel filter, exit-1 would never appear.
	require.Positive(t, c1, "exit-1 events must be emitted via pol-nodata (proves the kernel submitted them)")
	require.Equal(t, []string{"pol-nodata"}, m1,
		"exit-1 events must be excluded from pol-data by the userland exit_code filter, kept by pol-nodata")

	// The comm complement was dropped in the kernel (comm scope is kernel-enforced).
	require.Zero(t, cNone, "comm-complement exits must be dropped in the kernel")
}
