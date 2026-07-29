package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// These tests exercise the OVERFLOW path of the matched-rules model: an event with MORE THAN 64 rules.
// The kernel's matched_rules is a single u64 (rules 0-63); rules with ID >= 64 cannot be represented, so
// the kernel sets config.has_overflow and rules_matched() (filtering.h) returns true unconditionally -
// i.e. it OVER-SUBMITS every such event and lets userland's matchOverflowRules narrow the overflow words.
// Because the kernel filter is defeated for overflow events, these cases do NOT assert EventsFiltered==0
// (the complement is dropped in userland, not the kernel); they assert attribution instead.
//
// They run on ONE shared tracee via the withPolicies harness: each case applies its 70-policy set at
// RUNTIME (ApplyPolicy) and removes it afterwards, instead of starting a fresh tracee per case (~8s each).
// Applying 70 policies one-by-one also exercises the runtime-mutation path (stable rule IDs, filter-map
// reaping, version coherence) under a large, boundary-spanning rule set. Assertions are by policy NAME, so
// they do not depend on the exact runtime rule-ID assignment; the one case that needs a specific rule in
// the overflow words (binary scope) guarantees it by applying that policy last (highest ID).
//
// overflowPolicyCount is >64 so rule IDs 64.. live in the overflow words.
const overflowPolicyCount = 70

// overflowComm returns a distinct, unusual comm for policy index k (<= 15 chars, e.g. "ovf123_64").
func overflowComm(k int) string {
	return fmt.Sprintf("ovf%03d_%02d", os.Getpid()%1000, k)
}

func Test_PolicyOverflowShared(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	dir := t.TempDir()

	// One tracee for the whole test. A narrow base keeps the exit probe attached; the process data
	// store is enabled because the binary-scope case needs event.Executable.Path (harmless for the
	// exit-based cases). withRuntimePolicyChanges matches the other shared-tracee tests.
	base := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "ovf-base", fmt.Sprintf("ovfbase%d", os.Getpid()%100000)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base, withRuntimePolicyChanges, withProcessDataStore)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

	time.Sleep(2 * time.Second)

	// A10: 70 policies, each with a DISTINCT comm scope on sched_process_exit, so rule IDs span the
	// 64-boundary. Triggering every comm and asserting each is attributed to exactly its own policy
	// proves per-rule attribution across the boundary (the comms on overflow rule IDs are matched by
	// matchOverflowRules), and a complement (matching no policy) is not emitted.
	t.Run("distinct comms", func(t *testing.T) {
		comms := make([]string, overflowPolicyCount)
		bins := make([]string, overflowPolicyCount)
		pfs := make([]testutils.PolicyFileWithID, overflowPolicyCount)
		for k := 0; k < overflowPolicyCount; k++ {
			comms[k] = overflowComm(k)
			bins[k] = buildCommBinary(t, dir, comms[k])
			pfs[k] = exitScopePolicy(k+1, fmt.Sprintf("pol-%02d", k), comms[k])
		}
		commNone := fmt.Sprintf("ovfnone%d", os.Getpid()%1000)
		binNone := buildCommBinary(t, dir, commNone)

		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				require.NoError(t, exec.Command(binNone).Run()) // matches no policy
			}
			for k := 0; k < overflowPolicyCount; k++ {
				require.NoError(t, exec.Command(bins[k]).Run())
			}

			require.GreaterOrEqual(t, waitForExitComm(buf, comms[overflowPolicyCount-1], 1, 15*time.Second), 1,
				"the last policy's comm must be emitted")
			time.Sleep(1 * time.Second)

			// Every comm is attributed to exactly its own policy, including the ones on overflow IDs (>=64).
			for k := 0; k < overflowPolicyCount; k++ {
				m, c := exitPoliciesForComm(buf, comms[k])
				require.Positive(t, c, "comm for policy %d (%s) must be emitted", k, comms[k])
				require.Equal(t, []string{fmt.Sprintf("pol-%02d", k)}, m,
					"comm for policy %d must be attributed to its own policy only", k)
			}

			_, none := exitPoliciesForComm(buf, commNone)
			require.Zero(t, none, "complement (matches no policy) must not be emitted")
		})
	})

	// D3: 70 policies ALL sharing the same comm on sched_process_exit. A single matching exit matches
	// EVERY rule (spanning the 64-boundary) and must be attributed to all 70 policies. If the overflow
	// matcher dropped the overflow-word bits, those names would be missing - exact-set equality guards
	// the cross-boundary OR of the matched-rules bitmap.
	t.Run("cross boundary match", func(t *testing.T) {
		commAll := fmt.Sprintf("ovfall%d", os.Getpid()%1000)
		binAll := buildCommBinary(t, dir, commAll)

		names := make([]string, overflowPolicyCount)
		pfs := make([]testutils.PolicyFileWithID, overflowPolicyCount)
		for k := 0; k < overflowPolicyCount; k++ {
			names[k] = fmt.Sprintf("pol-%02d", k)
			pfs[k] = exitScopePolicy(k+1, names[k], commAll) // ALL the same comm
		}
		sort.Strings(names) // exitPoliciesForComm returns a sorted set

		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				require.NoError(t, exec.Command(binAll).Run())
			}

			require.GreaterOrEqual(t, waitForExitComm(buf, commAll, 1, 15*time.Second), 1,
				"the shared-comm exit must be emitted")
			time.Sleep(500 * time.Millisecond)

			m, c := exitPoliciesForComm(buf, commAll)
			require.Positive(t, c)
			require.Equal(t, names, m,
				"an exit matching all %d rules (spanning the 64-boundary) must be attributed to every policy", overflowPolicyCount)
		})
	})

	// Test_PolicyOverflowBinaryScope: a per-rule executable/binary scope is enforced for OVERFLOW rules
	// (ID >= 64), not just kernel-tracked ones. The binary-scoped policy is applied LAST of the 70, so its
	// rule lands in the overflow words. Without narrowOverflowBinaryScope, that overflow rule would match
	// every submitted exec and mis-attribute events whose binary does not match. Uses sched_process_exec so
	// the exec'ing process is alive and its binary path is resolvable (exit's process is already gone).
	t.Run("binary scope", func(t *testing.T) {
		commAll := fmt.Sprintf("ovbA%d", os.Getpid()%100000)
		commExec := fmt.Sprintf("ovbX%d", os.Getpid()%100000)
		buildCommBinary(t, dir, commAll)
		binExec := buildCommBinary(t, dir, commExec)
		binExecPath, err := filepath.EvalSymlinks(binExec)
		require.NoError(t, err)
		binAllPath := filepath.Join(dir, commAll)

		// overflowPolicyCount-1 comm policies (all match commAll) named "pol-*", plus ONE policy scoped by
		// executable, applied LAST so its rule ID lands in the overflow words.
		const commCount = overflowPolicyCount - 1
		pfs := make([]testutils.PolicyFileWithID, 0, overflowPolicyCount)
		commNames := make([]string, commCount)
		for k := 0; k < commCount; k++ {
			commNames[k] = fmt.Sprintf("pol-%02d", k)
			pfs = append(pfs, execScopePolicy(k+1, commNames[k], commAll))
		}
		execName := fmt.Sprintf("zzz-exec-%d", os.Getpid())
		pfs = append(pfs, execScopePolicy(overflowPolicyCount, execName, "", "executable="+binExecPath))
		sort.Strings(commNames)

		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				require.NoError(t, exec.Command(binAllPath).Run())  // comm=commAll, binary != binExecPath
				require.NoError(t, exec.Command(binExecPath).Run()) // binary == binExecPath, comm=commExec
			}

			// Positive control: the binary-scoped overflow rule matches its OWN binary's exec.
			require.GreaterOrEqual(t, waitForExecComm(buf, commExec, 1, 15*time.Second), 1,
				"the binary-scoped exec must be emitted")
			time.Sleep(500 * time.Millisecond)
			mExec, _ := execPoliciesForComm(buf, commExec)
			require.Equal(t, []string{execName}, mExec,
				"the binary-scoped overflow rule must match its own binary (and only it)")

			// The fix: binAll's binary is NOT the scoped one, so the executable overflow rule must NOT
			// match it. A leak here (execName present) means the overflow rule matched regardless of binary.
			mAll, cAll := execPoliciesForComm(buf, commAll)
			require.Positive(t, cAll, "the comm exec must be emitted")
			require.Equal(t, commNames, mAll,
				"binAll must be attributed to the comm policies only - the binary-scoped overflow rule must not leak")
		})
	})
}
