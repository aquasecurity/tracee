package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
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
func startTraceeWithPolicies(ctx context.Context, t *testing.T, policies []*policy.Policy, opts ...func(*config.Config)) (*tracee.Tracee, *testutils.EventBuffer, *streams.Stream) {
	t.Helper()

	cfg := config.Config{
		Capabilities:      &config.CapabilitiesConfig{BypassCaps: true},
		EnrichmentEnabled: false,
	}
	// opts let a test tweak the config (e.g. enable the userland process data store, which is off by
	// default here - it drives event.Executable.Path, needed by userland executable-scope narrowing).
	for _, o := range opts {
		o(&cfg)
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

const schedProcessExecName = "sched_process_exec"

// execScopePolicy is the sched_process_exec analogue of exitScopePolicy. Unlike exit, an exec event carries
// the (live) process's executable path, so userland binary-scope narrowing can be verified against it.
func execScopePolicy(id int, name, comm string, ruleFilters ...string) testutils.PolicyFileWithID {
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
				Rules:          []k8s.Rule{{Event: schedProcessExecName, Filters: ruleFilters}},
			},
		},
	}
}

// execPoliciesForComm is the sched_process_exec analogue of exitPoliciesForComm.
func execPoliciesForComm(buf *testutils.EventBuffer, comm string) (matched []string, count int) {
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != schedProcessExecName {
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

// waitForExecComm is the sched_process_exec analogue of waitForExitComm.
func waitForExecComm(buf *testutils.EventBuffer, comm string, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		if _, n := execPoliciesForComm(buf, comm); n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// withProcessDataStore enables the userland process tree DATA STORE (distinct from the kernel-side tree-scope
// filter). It is off by default in these tests, but it feeds event.Executable.Path from exec/fork events -
// which userland executable-scope narrowing needs. Production enables it by default. This is the first
// integration test to depend on it.
func withProcessDataStore(c *config.Config) {
	c.ProcessStore = process.ProcTreeConfig{
		Enabled:          true,
		Source:           process.SourceBoth,
		ProcessCacheSize: process.DefaultProcessCacheSize,
		ThreadCacheSize:  process.DefaultThreadCacheSize,
	}
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

// exitPolicyScopes builds a policy selecting sched_process_exit with arbitrary scope strings (e.g.
// "comm=x", "uid=1234") and optional per-event data filters.
func exitPolicyScopes(id int, name string, scopes []string, ruleFilters ...string) testutils.PolicyFileWithID {
	if ruleFilters == nil {
		ruleFilters = []string{}
	}
	return testutils.PolicyFileWithID{
		Id: id,
		PolicyFile: polv1beta1.PolicyFile{
			Metadata: polv1beta1.Metadata{Name: name},
			Spec: k8s.PolicySpec{
				Scope:          scopes,
				DefaultActions: []string{"log"},
				Rules:          []k8s.Rule{{Event: schedProcessExitName, Filters: ruleFilters}},
			},
		},
	}
}

// Test_PolicyScopeIdenticalUnionAttribution (scenario A3): two policies with the SAME comm scope on the
// same event. The identical kernel scope collapses to comm=A, and a matching exit is attributed to BOTH
// policies; the complement is dropped in the kernel.
func Test_PolicyScopeIdenticalUnionAttribution(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trc3a%d", os.Getpid())
	commNone := fmt.Sprintf("trc3n%d", os.Getpid())

	binA := buildCommBinary(t, t.TempDir(), commA)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-a1", commA),
		exitScopePolicy(2, "pol-a2", commA),
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

	require.GreaterOrEqual(t, waitForExitComm(buf, commA, runsMatch, 10*time.Second), runsMatch)

	matched, _ := exitPoliciesForComm(buf, commA)
	require.Equal(t, []string{"pol-a1", "pol-a2"}, matched,
		"a matching exit must be attributed to both identical-scope policies")

	_, none := exitPoliciesForComm(buf, commNone)
	require.Zero(t, none, "complement exits must be dropped in the kernel")

	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline)
}

// runAsUID runs bin as the given uid/gid (root only) and waits for it to exit.
func runAsUID(t *testing.T, bin string, uid uint32) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	_ = cmd.Run()
}

// buildAccessibleCommBinary builds a comm binary in a world-traversable dir so a non-root uid can exec it.
func buildAccessibleCommBinary(t *testing.T, comm string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "trcuid")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o755))
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return buildCommBinaryFrom(t, dir, comm, "/usr/bin/true")
}

// Test_PolicyScopeCrossDimensionUnion (scenario A7): two policies scoping DIFFERENT dimensions of the
// same event - P1 comm=A, P2 uid=U. The kernel submits an exit if comm==A OR uid==U; each event is
// attributed to the matching dimension's policy, and an exit matching neither is dropped in the kernel.
func Test_PolicyScopeCrossDimensionUnion(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	const uidU = 61234

	commA := fmt.Sprintf("trc7a%d", os.Getpid())    // matches P1 (comm); runs as root (uid 0 != U)
	commU := fmt.Sprintf("trc7u%d", os.Getpid())    // matches P2 (uid=U); comm != A
	commNone := fmt.Sprintf("trc7n%d", os.Getpid()) // matches neither

	binA := buildCommBinary(t, t.TempDir(), commA)
	binU := buildAccessibleCommBinary(t, commU)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitPolicyScopes(1, "pol-comm", []string{"comm=" + commA}),
		exitPolicyScopes(2, "pol-uid", []string{fmt.Sprintf("uid=%d", uidU)}),
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

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binNone).Run()) // neither dimension (root)
	}
	for i := 0; i < runs; i++ {
		runAsUID(t, binU, uidU) // uid dimension
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binA).Run()) // comm dimension
	}

	require.GreaterOrEqual(t, waitForExitComm(buf, commA, runs, 10*time.Second), runs, "comm=A exits emitted")
	require.GreaterOrEqual(t, waitForExitComm(buf, commU, runs, 10*time.Second), runs, "uid=U exits emitted")

	mA, _ := exitPoliciesForComm(buf, commA)
	mU, _ := exitPoliciesForComm(buf, commU)
	_, none := exitPoliciesForComm(buf, commNone)
	require.Equal(t, []string{"pol-comm"}, mA, "comm=A exit attributed to the comm policy only")
	require.Equal(t, []string{"pol-uid"}, mU, "uid=U exit attributed to the uid policy only")
	require.Zero(t, none, "exit matching neither dimension must be dropped in the kernel")
	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"the OR union {comm=A, uid=U} must gate submission in the kernel (complement never reaches userland)")
}

// Test_PolicyMatchedSubsetAttribution (scenario D2): five policies split across three comm scopes. An
// event must be attributed to EXACTLY the subset of policies whose scope it matches - not a superset
// (leaking unrelated policies) nor a subset (dropping matching ones). Complement is dropped in the kernel.
func Test_PolicyMatchedSubsetAttribution(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commX := fmt.Sprintf("trcd2x%d", os.Getpid())
	commY := fmt.Sprintf("trcd2y%d", os.Getpid())
	commZ := fmt.Sprintf("trcd2z%d", os.Getpid())
	commNone := fmt.Sprintf("trcd2n%d", os.Getpid())

	dir := t.TempDir()
	binX := buildCommBinary(t, dir, commX)
	binY := buildCommBinary(t, dir, commY)
	binZ := buildCommBinary(t, dir, commZ)
	binNone := buildCommBinary(t, dir, commNone)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "pol-x1", commX),
		exitScopePolicy(2, "pol-x2", commX),
		exitScopePolicy(3, "pol-y1", commY),
		exitScopePolicy(4, "pol-y2", commY),
		exitScopePolicy(5, "pol-z", commZ),
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
	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binNone).Run())
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binX).Run())
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binY).Run())
	}
	for i := 0; i < runs; i++ {
		require.NoError(t, exec.Command(binZ).Run())
	}

	require.GreaterOrEqual(t, waitForExitComm(buf, commZ, runs, 10*time.Second), runs)

	mX, _ := exitPoliciesForComm(buf, commX)
	mY, _ := exitPoliciesForComm(buf, commY)
	mZ, _ := exitPoliciesForComm(buf, commZ)
	_, none := exitPoliciesForComm(buf, commNone)

	require.Equal(t, []string{"pol-x1", "pol-x2"}, mX, "X event attributed to exactly the two X policies")
	require.Equal(t, []string{"pol-y1", "pol-y2"}, mY, "Y event attributed to exactly the two Y policies")
	require.Equal(t, []string{"pol-z"}, mZ, "Z event attributed to exactly the one Z policy")
	require.Zero(t, none, "complement dropped in the kernel")
	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline)
}

// emittedCountByComm counts buffered events with the given name whose process comm matches.
func emittedCountByComm(buf *testutils.EventBuffer, eventName, comm string) int {
	n := 0
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != eventName ||
			e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
			e.Workload.Process.Thread.Name != comm {
			continue
		}
		n++
	}
	return n
}

// Test_PolicyPerRuleScopeKernelPushdown proves that a PER-RULE scope filter (a scope key inside a rule's
// `filters:` list - rule.Data.ScopeFilter) is enforced IN THE KERNEL, not just user space. openat is
// selected with a per-rule comm filter (not a policy spec.scope). With the per-rule scope pushdown, the
// kernel drops every non-matching openat (of which there are a huge number system-wide) before
// submission, so EventsFiltered stays 0; matching openats still flow. Before the pushdown this filter
// was userland-only and the counter would climb with all openat activity.
func Test_PolicyPerRuleScopeKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trcpr%d", os.Getpid())
	commNone := fmt.Sprintf("trcpn%d", os.Getpid())
	binA := buildCommBinary(t, t.TempDir(), commA)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	// openat with a PER-RULE comm filter (rule `filters:`), global policy scope.
	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		{
			Id: 1,
			PolicyFile: polv1beta1.PolicyFile{
				Metadata: polv1beta1.Metadata{Name: "perrule"},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []k8s.Rule{{Event: "openat", Filters: []string{"comm=" + commA}}},
				},
			},
		},
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

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < 100; i++ {
		require.NoError(t, exec.Command(binNone).Run()) // complement openats (dropped in kernel)
	}
	for i := 0; i < 20; i++ {
		require.NoError(t, exec.Command(binA).Run()) // matching openats
	}

	// Positive control: matching openats are emitted (so a 0 delta means "kernel dropped", not "idle").
	deadline := time.Now().Add(10 * time.Second)
	for emittedCountByComm(buf, "openat", commA) == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	require.Positive(t, emittedCountByComm(buf, "openat", commA), "matching openat events must be emitted")

	// The per-rule comm scope is enforced in the kernel: every non-matching openat (our complement plus
	// all background openat activity) was dropped before submission, so none reached userland to be
	// filtered. A non-zero value means the per-rule scope leaked to user-space filtering.
	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"EventsFiltered moved: complement openat events reached userland, so the per-rule comm scope was not kernel-enforced")
}

// Test_PolicyPerRuleScopeDerivedEvent covers per-rule scope on a DERIVED event (net_packet_icmp). The
// per-rule comm is threaded onto the net base dependency rules and pushed to the kernel, so this guards
// the interaction with the net-event submission path (the a2 socket-bitmap fix): the matching per-rule
// comm must still capture the derived event (per-rule scope must not drop the base it needs), and a
// non-matching per-rule comm must not.
func Test_PolicyPerRuleScopeDerivedEvent(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		{
			Id: 1,
			PolicyFile: polv1beta1.PolicyFile{
				Metadata: polv1beta1.Metadata{Name: "icmp-ping"},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []k8s.Rule{{Event: "net_packet_icmp", Filters: []string{"comm=ping"}}},
				},
			},
		},
		{
			Id: 2,
			PolicyFile: polv1beta1.PolicyFile{
				Metadata: polv1beta1.Metadata{Name: "icmp-other"},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []k8s.Rule{{Event: "net_packet_icmp", Filters: []string{"comm=zzznotping"}}},
				},
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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

	// Generate ICMP from comm=ping until the derived event is captured (or timeout).
	deadline := time.Now().Add(20 * time.Second)
	for !hasMatchedEvent(buf, "net_packet_icmp", "ping", "icmp-ping") && time.Now().Before(deadline) {
		_ = exec.Command("ping", "-c1", "-W1", "0.0.0.0").Run() // outgoing echo request is captured
		time.Sleep(300 * time.Millisecond)
	}

	// The matching per-rule comm=ping policy must capture the derived net_packet_icmp (the per-rule scope
	// pushed onto the base must not drop it).
	require.True(t, hasMatchedEvent(buf, "net_packet_icmp", "ping", "icmp-ping"),
		"net_packet_icmp from ping must be captured by the per-rule comm=ping policy")

	// The non-matching per-rule comm policy must not match a ping's ICMP.
	require.False(t, hasMatchedEvent(buf, "net_packet_icmp", "ping", "icmp-other"),
		"net_packet_icmp from ping must NOT match the per-rule comm=zzznotping policy")
}

// Test_PolicyPerRuleBinaryScopeKernelPushdown proves that a PER-RULE executable/binary scope (a scope key
// inside a rule's `filters:` list) is enforced in the KERNEL: openat is selected with a per-rule
// executable filter, so the kernel drops every openat whose process binary is not the scoped one before
// submission (EventsFiltered stays 0), while openats from the scoped binary flow.
func Test_PolicyPerRuleBinaryScopeKernelPushdown(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	commA := fmt.Sprintf("trbin%d", os.Getpid())
	commNone := fmt.Sprintf("trbno%d", os.Getpid())
	binA := buildCommBinary(t, t.TempDir(), commA)
	binNone := buildCommBinary(t, t.TempDir(), commNone)

	// The kernel binary filter matches proc_info.binary.path (the resolved exec path).
	binAPath, err := filepath.EvalSymlinks(binA)
	require.NoError(t, err)
	binNonePath, err := filepath.EvalSymlinks(binNone)
	require.NoError(t, err)

	// openat with a PER-RULE executable filter (rule `filters:`), global policy scope.
	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{
		{
			Id: 1,
			PolicyFile: polv1beta1.PolicyFile{
				Metadata: polv1beta1.Metadata{Name: "perrule-bin"},
				Spec: k8s.PolicySpec{
					Scope:          []string{"global"},
					DefaultActions: []string{"log"},
					Rules:          []k8s.Rule{{Event: "openat", Filters: []string{"executable=" + binAPath}}},
				},
			},
		},
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

	baseline := trc.Stats().EventsFiltered.Get()

	for i := 0; i < 100; i++ {
		_ = exec.Command(binNonePath).Run() // complement: different binary -> dropped in kernel
	}
	for i := 0; i < 20; i++ {
		require.NoError(t, exec.Command(binAPath).Run()) // matching binary
	}

	// Positive control: openats from the scoped binary are emitted (comm equals the scoped binary's name).
	deadline := time.Now().Add(10 * time.Second)
	for emittedCountByComm(buf, "openat", commA) == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	require.Positive(t, emittedCountByComm(buf, "openat", commA),
		"openat events from the scoped binary must be emitted")

	// Kernel enforcement: every openat from a non-scoped binary (our complement plus all background
	// activity) was dropped before submission, so none reached userland to be filtered.
	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"EventsFiltered moved: openat from non-scoped binaries reached userland, so the per-rule executable scope was not kernel-enforced")
}
