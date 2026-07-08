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
	t.Logf("=== tracee STARTED: %s ===", t.Name())

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

// stopTraceeWithPolicies tears down a tracee started by startTraceeWithPolicies, logging its lifecycle so a run
// shows each test's tracee start/stop clearly (matching the shared-tracee logging in Test_EventFilters). Every
// shared-tracee test runs its own isolated tracee for the whole test; these bookend logs make that visible.
func stopTraceeWithPolicies(t *testing.T, trc *tracee.Tracee, stream *streams.Stream, cancel context.CancelFunc) {
	t.Helper()
	t.Logf("=== tracee STOPPING: %s ===", t.Name())
	trc.Unsubscribe(stream)
	cancel()
	if err := testutils.WaitForTraceeStop(trc); err != nil {
		t.Logf("Error stopping Tracee: %v", err)
	}
	t.Logf("=== tracee STOPPED: %s ===", t.Name())
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

// withRuntimePolicyChanges enables the capability that pre-loads the syscall dispatchers at init, so syscall
// events (which no exit-only base selects) can be selected at runtime via ApplyPolicy without "can't attach
// before loaded". See docs/runtime-syscall-selection-gap.md.
func withRuntimePolicyChanges(c *config.Config) {
	c.RuntimePolicyChanges = true
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

// openatPerRuleCommPolicy builds a global-scope policy with a single openat rule carrying a per-rule comm
// filter (rule `filters:`), used to exercise per-rule scope kernel pushdown.
func openatPerRuleCommPolicy(id int, name, comm string) testutils.PolicyFileWithID {
	return testutils.PolicyFileWithID{
		Id: id,
		PolicyFile: polv1beta1.PolicyFile{
			Metadata: polv1beta1.Metadata{Name: name},
			Spec: k8s.PolicySpec{
				Scope:          []string{"global"},
				DefaultActions: []string{"log"},
				Rules:          []k8s.Rule{{Event: "openat", Filters: []string{"comm=" + comm}}},
			},
		},
	}
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
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

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
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

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
