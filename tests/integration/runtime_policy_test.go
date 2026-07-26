package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// These tests exercise RUNTIME policy changes on a running tracee (no restart): Tracee.ApplyPolicy /
// RemovePolicy. Each asserts the change takes effect end to end - the userland rule swap (PolicyManager
// atomic snapshot) AND the kernel re-push (populateFilterMaps), plus probe attach for a newly-selected event.
//
// They use sched_process_exit/exec, whose comm comes from the kernel event context (not the process data
// store), so they need no ProcessStore config.

// countEventComm counts buffered events of the given name whose process comm matches.
func countEventComm(buf *testutils.EventBuffer, eventName, comm string) int {
	n := 0
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != eventName {
			continue
		}
		if e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
			e.Workload.Process.Thread.Name != comm {
			continue
		}
		n++
	}
	return n
}

// waitEventComm waits until at least want events of eventName with the given comm are buffered (or timeout).
func waitEventComm(buf *testutils.EventBuffer, eventName, comm string, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		if n := countEventComm(buf, eventName, comm); n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Test_RuntimeApplyPolicyTakesEffect: apply a NEW policy on a running tracee and prove the kernel re-push took
// effect - an event that matched no policy before (so the kernel dropped it) starts being emitted after apply.
func Test_RuntimeApplyPolicyTakesEffect(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commBase := fmt.Sprintf("rtaA%d", os.Getpid()%100000)
	commAdd := fmt.Sprintf("rtaB%d", os.Getpid()%100000)
	binBase := buildCommBinary(t, dir, commBase)
	binAdd := buildCommBinary(t, dir, commAdd)

	base := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "base", commBase)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Before apply: commAdd matches no policy -> kernel filters its exit out -> not emitted.
	for i := 0; i < 3; i++ {
		require.NoError(t, exec.Command(binAdd).Run())
	}
	require.NoError(t, exec.Command(binBase).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commBase, 1, 10*time.Second), 1, "base policy must emit")
	require.Zero(t, countEventComm(buf, schedProcessExitName, commAdd),
		"commAdd must not be emitted before its policy is applied")

	// Apply a new policy at runtime scoping commAdd.
	added := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(2, "added", commAdd)})[0]
	name, err := trc.ApplyPolicy(added)
	require.NoError(t, err)
	require.Equal(t, "added", name)
	require.Contains(t, trc.ListPolicies(), "added", "applied policy must be listed")

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// After apply: commAdd's exit now passes the (re-pushed) kernel comm filter and matches the added policy.
	for i := 0; i < 5; i++ {
		require.NoError(t, exec.Command(binAdd).Run())
	}
	require.GreaterOrEqual(t, waitForExitComm(buf, commAdd, 1, 10*time.Second), 1,
		"the runtime-applied policy must take effect (kernel re-push)")
	m, _ := exitPoliciesForComm(buf, commAdd)
	require.Equal(t, []string{"added"}, m, "commAdd must be attributed to the applied policy only")
}

// Test_RuntimeRemovePolicyTakesEffect: remove a policy on a running tracee and prove its events stop.
func Test_RuntimeRemovePolicyTakesEffect(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commKeep := fmt.Sprintf("rtrK%d", os.Getpid()%100000)
	commDrop := fmt.Sprintf("rtrD%d", os.Getpid()%100000)
	binKeep := buildCommBinary(t, dir, commKeep)
	binDrop := buildCommBinary(t, dir, commDrop)

	initial := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "keep", commKeep),
		exitScopePolicy(2, "drop", commDrop),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, initial)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Before remove: commDrop is emitted (matches the "drop" policy).
	require.NoError(t, exec.Command(binDrop).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commDrop, 1, 10*time.Second), 1, "drop policy must emit before removal")

	// Remove the "drop" policy at runtime.
	require.NoError(t, trc.RemovePolicy("drop"))
	require.NotContains(t, trc.ListPolicies(), "drop", "removed policy must not be listed")

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// After remove: commDrop matches nothing -> the kernel filters its exit out (re-push). "keep" still works.
	for i := 0; i < 5; i++ {
		require.NoError(t, exec.Command(binDrop).Run())
	}
	require.NoError(t, exec.Command(binKeep).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commKeep, 1, 10*time.Second), 1, "keep policy must still emit")
	require.Zero(t, countEventComm(buf, schedProcessExitName, commDrop),
		"the runtime-removed policy must stop taking effect (kernel re-push)")
}

// Test_RuntimeUpdatePolicyTakesEffect: re-apply an existing policy name with a different scope (ApplyPolicy's
// upsert -> UpdatePolicy path) and prove the new scope matches while the old no longer does.
func Test_RuntimeUpdatePolicyTakesEffect(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commOld := fmt.Sprintf("rtuO%d", os.Getpid()%100000)
	commNew := fmt.Sprintf("rtuN%d", os.Getpid()%100000)
	binOld := buildCommBinary(t, dir, commOld)
	binNew := buildCommBinary(t, dir, commNew)

	initial := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "p", commOld)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, initial)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Before update: commOld matches, commNew does not.
	require.NoError(t, exec.Command(binOld).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commOld, 1, 10*time.Second), 1, "original scope must emit")

	// Update policy "p" to scope commNew (same name -> upsert -> UpdatePolicy).
	updated := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "p", commNew)})[0]
	name, err := trc.ApplyPolicy(updated)
	require.NoError(t, err)
	require.Equal(t, "p", name)

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// After update: commNew matches, commOld no longer does.
	for i := 0; i < 5; i++ {
		require.NoError(t, exec.Command(binNew).Run())
		require.NoError(t, exec.Command(binOld).Run())
	}
	require.GreaterOrEqual(t, waitForExitComm(buf, commNew, 1, 10*time.Second), 1, "updated scope must take effect")
	require.Zero(t, countEventComm(buf, schedProcessExitName, commOld),
		"the old scope must no longer match after update")
}

// Test_RuntimeApplyPolicySelectsNewEvent: apply a policy selecting an event no user policy selected before
// (sched_process_exec, while the base selects only sched_process_exit) and prove the event starts being
// emitted. Precision note: exec's PROBE is attached from init regardless (the internal bootstrap policy
// always collects exec/fork/exit), so what this proves is user-rule selection taking effect at runtime -
// before apply, exec events are collected but emitted to no one; after apply, they are emitted and
// attributed. The genuine runtime probe-attach case is the syscall one
// (Test_RuntimeApplyPolicyAttachesSyscallProbe), whose dispatcher is not attached before apply.
func Test_RuntimeApplyPolicySelectsNewEvent(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commBase := fmt.Sprintf("rtpA%d", os.Getpid()%100000)
	commProbe := fmt.Sprintf("rtpP%d", os.Getpid()%100000)
	binBase := buildCommBinary(t, dir, commBase)
	binProbe := buildCommBinary(t, dir, commProbe)

	// Base selects only sched_process_exit -> no user rule on sched_process_exec.
	base := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "base", commBase)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Before apply: no sched_process_exec is emitted (no user rule selects it).
	for i := 0; i < 3; i++ {
		require.NoError(t, exec.Command(binProbe).Run())
	}
	require.NoError(t, exec.Command(binBase).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commBase, 1, 10*time.Second), 1, "base exit policy must emit")
	require.Zero(t, countEventComm(buf, schedProcessExecName, commProbe),
		"sched_process_exec must not be emitted before a user policy selects it")

	// Apply a policy selecting sched_process_exec -> the event must start being emitted.
	execPol := testutils.NewPolicies([]testutils.PolicyFileWithID{execScopePolicy(2, "exec-added", commProbe)})[0]
	_, err := trc.ApplyPolicy(execPol)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// After apply: running binProbe now produces emitted sched_process_exec events.
	for i := 0; i < 5; i++ {
		require.NoError(t, exec.Command(binProbe).Run())
	}
	require.GreaterOrEqual(t, waitEventComm(buf, schedProcessExecName, commProbe, 1, 10*time.Second), 1,
		"applying a policy selecting a new event must make it emit at runtime")
}

// Test_RuntimeRemovePolicyStopsEmission is the mirror of Test_RuntimeApplyPolicySelectsNewEvent: removing the
// only USER policy that selected an event must make that event stop being EMITTED. Note the precise claim:
// sched_process_exec is always collected by the internal bootstrap policy, so its probe never detaches and
// the event keeps reaching userland regardless (which also means EventsFiltered is not a signal here - the
// bootstrap bit keeps the bitmap non-empty). What removal must guarantee, and what this asserts, is that the
// removed policy's rule is gone: no exec event is emitted (attributed) for it afterwards. That isolation
// property is the prerequisite for the shared-tracee foundation - a leftover rule would leak the removed
// policy's name into sibling cases' attribution sets.
func Test_RuntimeRemovePolicyStopsEmission(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commBase := fmt.Sprintf("rtdA%d", os.Getpid()%100000)
	commExec := fmt.Sprintf("rtdE%d", os.Getpid()%100000)
	binBase := buildCommBinary(t, dir, commBase)
	binExec := buildCommBinary(t, dir, commExec)

	// Base selects only sched_process_exit; the sched_process_exec probe is attached solely by the exec
	// policy applied below, so removing that policy deselects the exec probe entirely.
	base := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "base", commBase)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Apply an exec policy -> the exec probe attaches and sched_process_exec for commExec fires.
	execPol := testutils.NewPolicies([]testutils.PolicyFileWithID{execScopePolicy(2, "exec-p", commExec)})[0]
	_, err := trc.ApplyPolicy(execPol)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	buf.Clear()
	for i := 0; i < 5; i++ {
		require.NoError(t, exec.Command(binExec).Run())
	}
	require.GreaterOrEqual(t, waitEventComm(buf, schedProcessExecName, commExec, 1, 10*time.Second), 1,
		"exec policy must select and emit sched_process_exec while applied")

	// Remove it -> sched_process_exec must stop reaching userland.
	require.NoError(t, trc.RemovePolicy("exec-p"))
	require.NotContains(t, trc.ListPolicies(), "exec-p", "removed policy must not be listed")

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// The base still runs, so exec heavily: every one of these would emit if the removed policy's exec
	// rule were still in place.
	for i := 0; i < 20; i++ {
		require.NoError(t, exec.Command(binExec).Run())
	}
	require.NoError(t, exec.Command(binBase).Run()) // base exit still works (proves tracee is live)
	require.GreaterOrEqual(t, waitForExitComm(buf, commBase, 1, 10*time.Second), 1, "base exit policy must still emit")

	time.Sleep(1 * time.Second) // allow any straggler exec events to arrive before asserting absence

	require.Zero(t, countEventComm(buf, schedProcessExecName, commExec),
		"after removal, sched_process_exec must no longer be emitted (the removed policy's rule survived)")
}

// Test_RuntimeApplyPolicyAttachesSyscallProbe verifies runtime syscall selection (the RuntimePolicyChanges
// pre-load). Syscall events ride the shared raw_syscalls dispatchers; with no syscall selected at init those programs are
// not loaded, so selecting a syscall at runtime fails with "can't attach before loaded". With
// RuntimePolicyChanges enabled the dispatchers are pre-loaded, so applying a policy that selects openat at
// runtime succeeds and the event fires. This is the syscall analogue of Test_RuntimeApplyPolicySelectsNewEvent
// (which covers a dedicated-tracepoint event, sched_process_exec, that is loaded at init regardless).
func Test_RuntimeApplyPolicyAttachesSyscallProbe(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commBase := fmt.Sprintf("rtsA%d", os.Getpid()%100000)
	commSys := fmt.Sprintf("rtsS%d", os.Getpid()%100000)
	binBase := buildCommBinary(t, dir, commBase)
	binSys := buildCommBinary(t, dir, commSys)

	// Base selects only sched_process_exit (no syscall). withRuntimePolicyChanges pre-loads the syscall
	// dispatchers so a runtime syscall selection can attach.
	base := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "base", commBase)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base, withRuntimePolicyChanges)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Sanity: the base is live.
	require.NoError(t, exec.Command(binBase).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commBase, 1, 10*time.Second), 1, "base exit policy must emit")

	// Apply a policy selecting the SYSCALL event openat at runtime. Without Option A this errors with
	// "failed to select event openat" ("can't attach before loaded").
	openatPol := testutils.NewPolicies([]testutils.PolicyFileWithID{openatPerRuleCommPolicy(2, "openat-p", commSys)})[0]
	_, err := trc.ApplyPolicy(openatPol)
	require.NoError(t, err, "runtime selection of a syscall event must succeed when RuntimePolicyChanges is enabled")
	require.Contains(t, trc.ListPolicies(), "openat-p", "applied syscall policy must be listed")

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// Running binSys triggers openats with comm=commSys -> the dispatcher (loaded at init, attached now) fires.
	for i := 0; i < 20; i++ {
		require.NoError(t, exec.Command(binSys).Run())
	}
	require.GreaterOrEqual(t, waitEventComm(buf, "openat", commSys, 1, 10*time.Second), 1,
		"applying a syscall-event policy at runtime must attach the dispatcher and emit the event")
}

// Test_RuntimeConcurrentPolicyChurn is the soundness stress test for per-event snapshot retention: it runs a
// stable workload while a goroutine rapidly applies and removes another policy ON THE SAME EVENT. The churn
// policy is named "aaa-churn" so it sorts BEFORE "base"; toggling it flips base's sched_process_exit rule ID
// (0<->1) on every swap. An in-flight stable event therefore has its matched-rules bit set under one rule-ID
// layout and read at the sink possibly after a swap - without per-event snapshot threading the bit would be
// interpreted against the wrong version, mis-attributing or (bit points at a now-absent rule) dropping the
// event. Assertions: every stable exit captured during churn attributes to exactly {base} (soundness); and
// after churn stops, base still emits in a clean window (liveness). The re-push window drops an env-dependent
// share of exits under churn, so that drop count is NOT asserted. Run under -race so torn reads are caught too.
func Test_RuntimeConcurrentPolicyChurn(t *testing.T) {
	// Guards the kernel-generation <-> userland-decode skew that STABLE RULE IDs close: the kernel computes the
	// matched-rules bitmap at event GENERATION and the event waits in the perf buffer until userland DECODE.
	// "aaa-churn" sorts before "base", but rule IDs no longer renumber on add/remove (base keeps its ID, the
	// churn policy keeps its own), so the kernel's bit always resolves to the same policy regardless of when
	// userland reads it. Previously this mis-attributed a stable exit to aaa-churn; it must not now.
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commStable := fmt.Sprintf("rccS%d", os.Getpid()%100000)
	commChurn := fmt.Sprintf("rccC%d", os.Getpid()%100000)
	binStable := buildCommBinary(t, dir, commStable)

	base := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "base", commStable)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Churn goroutine: apply/remove "aaa-churn" (same event, different comm) in a tight loop.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		churn := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(2, "aaa-churn", commChurn)})[0]
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := trc.ApplyPolicy(churn); err != nil {
				t.Errorf("apply churn policy: %v", err)
				return
			}
			if err := trc.RemovePolicy("aaa-churn"); err != nil {
				t.Errorf("remove churn policy: %v", err)
				return
			}
			time.Sleep(3 * time.Millisecond)
		}
	}()

	// Fire the stable workload continuously during the churn. The re-push windows drop an
	// environment-dependent share of exits, so keep running batches (churn still active) until at least
	// one stable exit survives - the soundness loop below is "the property under test" and a run where
	// churnSeen==0 would exercise nothing. The batch cap keeps a pathological environment from looping
	// forever; hitting it fails the test honestly instead of green-lighting an empty check.
	const batchRuns = 100
	const maxBatches = 5
	survived := 0
	for batch := 0; batch < maxBatches && survived == 0; batch++ {
		for i := 0; i < batchRuns; i++ {
			require.NoError(t, exec.Command(binStable).Run())
		}
		survived = waitForExitComm(buf, commStable, 1, 5*time.Second)
	}

	close(stop)
	wg.Wait()
	_ = trc.RemovePolicy("aaa-churn") // ensure it is gone regardless of loop timing
	time.Sleep(1 * time.Second)       // let stragglers drain

	// SOUNDNESS (the property under test): every stable exit CAPTURED during churn attributes to exactly {base}
	// - never mis-attributed to the churn policy, never read against a version where base's rule ID had shifted.
	// Assert on whatever survived, not a count: every swap re-pushes ALL kernel filter maps, so the re-push
	// window drops an environment-dependent share of exits (much higher on slow/loaded CI). That drop rate is
	// noise, not a soundness signal - a count floor here is what made this test flaky.
	churnSeen := 0
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != schedProcessExitName ||
			e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
			e.Workload.Process.Thread.Name != commStable {
			continue
		}
		churnSeen++
		var got []string
		if e.Policies != nil {
			got = append([]string(nil), e.Policies.Matched...)
			sort.Strings(got)
		}
		require.Equal(t, []string{"base"}, got,
			"stable exit attributed to %v under churn - snapshot version leaked across a swap", got)
	}
	// The floor that keeps this test honest: zero survivors means the soundness loop above ran zero
	// iterations and the test proved nothing. The batched workload retries make this effectively
	// unreachable outside a pathological environment - which should be a failure, not a silent pass.
	require.Positive(t, churnSeen,
		"no stable exits survived %d batches of %d runs under churn - attribution-under-churn was not exercised",
		maxBatches, batchRuns)
	t.Logf("churn soundness: %d stable exits captured during churn, all attributed to {base}", churnSeen)

	// LIVENESS (drop-independent): with churn stopped, base must still emit. A clean window - no map rewrites
	// racing the workload - is the reliable "the churn didn't leave base broken or hung" check; it does not
	// depend on the churn drop rate. Post-churn exits must also attribute to exactly {base}.
	buf.Clear()
	for i := 0; i < 10; i++ {
		require.NoError(t, exec.Command(binStable).Run())
	}
	require.GreaterOrEqual(t, waitForExitComm(buf, commStable, 1, 10*time.Second), 1,
		"base policy stopped emitting after churn - the runtime changes left it broken")
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != schedProcessExitName ||
			e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
			e.Workload.Process.Thread.Name != commStable {
			continue
		}
		var got []string
		if e.Policies != nil {
			got = append([]string(nil), e.Policies.Matched...)
			sort.Strings(got)
		}
		require.Equal(t, []string{"base"}, got, "post-churn stable exit mis-attributed to %v", got)
	}
}
