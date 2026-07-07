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

	"github.com/aquasecurity/tracee/tests/testutils"
)

// These tests exercise RUNTIME policy changes on a RUNNING tracee - no restart. They are the first integration
// coverage of Tracee.ApplyPolicy / RemovePolicy (the userland side of the runtime policy-change work) and the
// seed of a shared-tracee test foundation. Each asserts that a change actually TAKES EFFECT end to end: the
// userland rule swap (PolicyManager + atomic snapshot) AND the kernel re-push (populateFilterMaps), plus probe
// attach for a newly-selected event.
//
// Note: these use sched_process_exit / sched_process_exec, whose comm comes from the kernel event context
// (not the userland process data store), so they need no ProcessStore config.

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
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

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
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

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
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

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

// Test_RuntimeApplyPolicyAttachesProbe: apply a policy selecting an event whose probe the initial policy set
// did NOT attach (sched_process_exec vs sched_process_exit), and prove the probe is attached at runtime (via
// the shared dependency-manager watcher) so the event starts firing.
func Test_RuntimeApplyPolicyAttachesProbe(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	commBase := fmt.Sprintf("rtpA%d", os.Getpid()%100000)
	commProbe := fmt.Sprintf("rtpP%d", os.Getpid()%100000)
	binBase := buildCommBinary(t, dir, commBase)
	binProbe := buildCommBinary(t, dir, commProbe)

	// Base selects only sched_process_exit -> the sched_process_exec probe is NOT attached.
	base := testutils.NewPolicies([]testutils.PolicyFileWithID{exitScopePolicy(1, "base", commBase)})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	// Before apply: no sched_process_exec is collected at all (event not selected, probe not attached).
	for i := 0; i < 3; i++ {
		require.NoError(t, exec.Command(binProbe).Run())
	}
	require.NoError(t, exec.Command(binBase).Run())
	require.GreaterOrEqual(t, waitForExitComm(buf, commBase, 1, 10*time.Second), 1, "base exit policy must emit")
	require.Zero(t, countEventComm(buf, schedProcessExecName, commProbe),
		"sched_process_exec must not be collected before its policy is applied (probe not attached)")

	// Apply a policy selecting sched_process_exec -> its probe must attach at runtime.
	execPol := testutils.NewPolicies([]testutils.PolicyFileWithID{execScopePolicy(2, "exec-added", commProbe)})[0]
	_, err := trc.ApplyPolicy(execPol)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	buf.Clear()

	// After apply: running binProbe now produces sched_process_exec events -> the probe attached at runtime.
	for i := 0; i < 5; i++ {
		require.NoError(t, exec.Command(binProbe).Run())
	}
	require.GreaterOrEqual(t, waitEventComm(buf, schedProcessExecName, commProbe, 1, 10*time.Second), 1,
		"applying a policy for a new event must attach its probe at runtime")
}

// Test_RuntimeRemovePolicyDetachesProbe is the mirror of Test_RuntimeApplyPolicyAttachesProbe: removing the
// only policy that selected an event must make that event STOP reaching userland. It asserts the observable
// guarantee (not the internal probe state): after removal the event is no longer emitted AND it does not move
// EventsFiltered - i.e. the deselected event is dropped at/before submission, not flooding userland to be
// filtered there. That property is the prerequisite for migrating probe-churning cases (e.g. openat) onto the
// shared-tracee foundation: a leftover selection would pollute sibling cases' EventsFiltered deltas.
func Test_RuntimeRemovePolicyDetachesProbe(t *testing.T) {
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
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

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

	baseline := trc.Stats().EventsFiltered.Get()

	// The base still runs, so exec heavily: every one of these would emit if the exec probe were still
	// selecting/submitting after removal.
	for i := 0; i < 20; i++ {
		require.NoError(t, exec.Command(binExec).Run())
	}
	require.NoError(t, exec.Command(binBase).Run()) // base exit still works (proves tracee is live)
	require.GreaterOrEqual(t, waitForExitComm(buf, commBase, 1, 10*time.Second), 1, "base exit policy must still emit")

	time.Sleep(1 * time.Second) // allow any straggler exec events to arrive before asserting absence

	require.Zero(t, countEventComm(buf, schedProcessExecName, commExec),
		"after removal, sched_process_exec must no longer reach userland (event deselected on RemovePolicy)")
	require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
		"EventsFiltered moved after removal: a deselected event is still reaching userland, which would pollute sibling cases")
}
