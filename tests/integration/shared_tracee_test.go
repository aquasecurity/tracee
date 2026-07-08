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

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// This file seeds the SHARED-TRACEE test foundation: instead of starting and stopping a tracee per test case
// (~6-8s of lifecycle each), one tracee runs for the whole test and each case applies its policy at runtime,
// runs its workload, and removes the policy - proven safe by the Test_Runtime* tests. withPolicy is the
// primitive; Test_SharedTraceePolicyFoundation is the proof of shape (two isolated cases on one tracee).

// withPolicies applies each policy to a running tracee, runs fn with a freshly-cleared buffer, then removes
// them all (reverse apply order) and clears the buffer. It is the building block of the shared-tracee
// foundation: a case swaps its policies in and out at runtime rather than restarting tracee.
func withPolicies(t *testing.T, trc *tracee.Tracee, buf *testutils.EventBuffer, pfs []testutils.PolicyFileWithID, fn func(t *testing.T)) {
	t.Helper()

	pols := testutils.NewPolicies(pfs)
	applied := make([]string, 0, len(pols))

	defer func() {
		for i := len(applied) - 1; i >= 0; i-- {
			require.NoError(t, trc.RemovePolicy(applied[i]), "remove policy %q", applied[i])
			require.NotContains(t, trc.ListPolicies(), applied[i], "removed policy must not be listed")
		}
		t.Logf("  <<< shared tracee: removed policies at runtime (no restart): %v", applied)
		buf.Clear()
	}()

	for _, p := range pols {
		name, err := trc.ApplyPolicy(p)
		require.NoError(t, err, "apply policy")
		require.Contains(t, trc.ListPolicies(), name, "applied policy must be listed")
		applied = append(applied, name)
	}
	t.Logf("  >>> shared tracee: applied policies at runtime (no restart): %v", applied)

	// Let the kernel re-push (and any probe attach) settle, then start from a clean buffer.
	time.Sleep(300 * time.Millisecond)
	buf.Clear()

	fn(t)
}

// withPolicy is the single-policy convenience wrapper over withPolicies.
func withPolicy(t *testing.T, trc *tracee.Tracee, buf *testutils.EventBuffer, pf testutils.PolicyFileWithID, fn func(t *testing.T)) {
	t.Helper()
	withPolicies(t, trc, buf, []testutils.PolicyFileWithID{pf}, fn)
}

// Test_SharedTraceePolicyFoundation runs multiple policy cases against a SINGLE tracee via withPolicy, proving
// the pattern: each case's policy takes effect while active, and is fully cleaned up afterwards (isolation) -
// the second case runs the first case's binary and asserts it no longer matches, since the first policy was
// removed (which also confirms the removal re-pushed the kernel filter).
func Test_SharedTraceePolicyFoundation(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()
	comm1 := fmt.Sprintf("sh1_%d", os.Getpid()%100000)
	comm2 := fmt.Sprintf("sh2_%d", os.Getpid()%100000)
	bin1 := buildCommBinary(t, dir, comm1)
	bin2 := buildCommBinary(t, dir, comm2)

	// One tracee for the whole test. A dummy base policy keeps the sched_process_exit probe attached; each
	// case below applies its own policy at runtime.
	base := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "base", fmt.Sprintf("shbase%d", os.Getpid()%100000)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
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

	// Case 1: a comm-scoped exit policy attributes its comm to itself.
	t.Run("case1 takes effect", func(t *testing.T) {
		withPolicy(t, trc, buf, exitScopePolicy(10, "case-1", comm1), func(t *testing.T) {
			require.NoError(t, exec.Command(bin1).Run())
			require.GreaterOrEqual(t, waitForExitComm(buf, comm1, 1, 10*time.Second), 1, "case-1 policy must emit")
			m, _ := exitPoliciesForComm(buf, comm1)
			require.Equal(t, []string{"case-1"}, m, "comm1 must be attributed to case-1 only")
		})
	})

	// Case 2: a different policy - and it must be isolated from case 1, whose policy withPolicy removed.
	t.Run("case2 isolated from case1", func(t *testing.T) {
		withPolicy(t, trc, buf, exitScopePolicy(11, "case-2", comm2), func(t *testing.T) {
			for i := 0; i < 5; i++ {
				require.NoError(t, exec.Command(bin1).Run()) // case-1's binary; its policy is gone now
				require.NoError(t, exec.Command(bin2).Run())
			}
			require.GreaterOrEqual(t, waitForExitComm(buf, comm2, 1, 10*time.Second), 1, "case-2 policy must emit")
			m, _ := exitPoliciesForComm(buf, comm2)
			require.Equal(t, []string{"case-2"}, m, "comm2 must be attributed to case-2 only")
			require.Zero(t, countEventComm(buf, schedProcessExitName, comm1),
				"comm1 must not be emitted - case-1's policy was removed (isolation + kernel re-push)")
		})
	})
}
