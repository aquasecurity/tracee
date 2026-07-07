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

// Test_PolicyScopeShared migrates the single-config scope-pushdown cases onto ONE tracee via the shared-tracee
// harness (withPolicy/withPolicies): each case applies its policies at runtime, asserts attribution AND kernel
// pushdown (the EventsFiltered delta - the complement is dropped in the kernel, so it never moves the userland
// counter), then removes the policies. This replaces the per-test tracee start/stop (~6-8s each) for this
// class. Detector-scope and structural-config tests stay per-instance (detectors are init-time only).
//
// These use sched_process_exit, whose comm comes from the kernel event context (no process data store needed).
// A dummy narrow base policy keeps the exit probe attached without broadening the kernel comm filter.
func Test_PolicyScopeShared(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	binDir := t.TempDir()

	base := testutils.NewPolicies([]testutils.PolicyFileWithID{
		exitScopePolicy(1, "base", fmt.Sprintf("pss-base%d", os.Getpid()%100000)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
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

	const (
		runsMatch = 15
		runsNone  = 100
	)

	// A2 (was Test_PolicyScopeSingleKernelPushdown): single policy scoped comm=A. Matching exits attributed
	// to pol-a; the complement is dropped in the kernel (EventsFiltered delta stays 0).
	t.Run("single kernel pushdown", func(t *testing.T) {
		commA := fmt.Sprintf("pss1a%d", os.Getpid())
		commNone := fmt.Sprintf("pss1n%d", os.Getpid())
		binA := buildCommBinary(t, binDir, commA)
		binNone := buildCommBinary(t, binDir, commNone)

		withPolicy(t, trc, buf, exitScopePolicy(10, "pol-a", commA), func(t *testing.T) {
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
				"EventsFiltered moved: complement reached userland, so scope comm=%s was not kernel-enforced", commA)
		})
	})

	// A4 (was Test_PolicyScopeUnionKernelPushdown): two policies scoping DISTINCT comms. The kernel filter is
	// the union {A,B}: A-exits attributed to pol-a, B-exits to pol-b, complement still kernel-dropped.
	t.Run("union kernel pushdown", func(t *testing.T) {
		commA := fmt.Sprintf("pss2a%d", os.Getpid())
		commB := fmt.Sprintf("pss2b%d", os.Getpid())
		commNone := fmt.Sprintf("pss2n%d", os.Getpid())
		binA := buildCommBinary(t, binDir, commA)
		binB := buildCommBinary(t, binDir, commB)
		binNone := buildCommBinary(t, binDir, commNone)

		pfs := []testutils.PolicyFileWithID{
			exitScopePolicy(11, "pol-a", commA),
			exitScopePolicy(12, "pol-b", commB),
		}
		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
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
				"EventsFiltered moved: the union comm filter {%s,%s} did not cleanly gate submission", commA, commB)
		})
	})
}
