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
	// withRuntimePolicyChanges pre-loads the syscall dispatchers so the per-rule openat case below can select a
	// syscall event at runtime; harmless for the exit-based cases.
	trc, buf, stream := startTraceeWithPolicies(ctx, t, base, withRuntimePolicyChanges)
	defer stopTraceeWithPolicies(t, trc, stream, cancel)

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

	// A5 (was Test_PolicyScopeUnionDefeatKernelPushdown): scoped comm=A plus a BROAD (unscoped) policy. The
	// broad rule defeats the kernel filter - the complement is submitted and emitted - yet attribution stays
	// exact and EventsFiltered stays 0 (every submitted event matches at least the broad rule).
	t.Run("union defeat", func(t *testing.T) {
		commA := fmt.Sprintf("trc5a%d", os.Getpid())
		commNone := fmt.Sprintf("trc5n%d", os.Getpid())
		binA := buildCommBinary(t, binDir, commA)
		binNone := buildCommBinary(t, binDir, commNone)

		pfs := []testutils.PolicyFileWithID{
			exitScopePolicy(20, "pol-a", commA),
			exitScopePolicy(21, "pol-broad", ""), // no scope -> matches every workload
		}
		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			baseline := trc.Stats().EventsFiltered.Get()

			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binNone).Run())
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binA).Run())
			}

			require.GreaterOrEqual(t, waitForExitComm(buf, commA, 15, 10*time.Second), 15)
			require.GreaterOrEqual(t, waitForExitComm(buf, commNone, 15, 10*time.Second), 15,
				"broad policy must cause the complement to be submitted (kernel filter defeated)")

			matchedA, _ := exitPoliciesForComm(buf, commA)
			matchedNone, _ := exitPoliciesForComm(buf, commNone)
			require.Equal(t, []string{"pol-a", "pol-broad"}, matchedA, "A-exit matches both the scoped and broad policy")
			require.Equal(t, []string{"pol-broad"}, matchedNone, "complement exit matches only the broad policy")

			require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
				"EventsFiltered moved unexpectedly: with a broad rule present every event should match a rule")
		})
	})

	// Was Test_PolicyScopeIdenticalUnionAttribution: two policies with the SAME comm scope; a matching exit is
	// attributed to both, complement kernel-dropped.
	t.Run("identical union attribution", func(t *testing.T) {
		commA := fmt.Sprintf("trc3a%d", os.Getpid())
		commNone := fmt.Sprintf("trc3n%d", os.Getpid())
		binA := buildCommBinary(t, binDir, commA)
		binNone := buildCommBinary(t, binDir, commNone)

		pfs := []testutils.PolicyFileWithID{
			exitScopePolicy(22, "pol-a1", commA),
			exitScopePolicy(23, "pol-a2", commA),
		}
		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			baseline := trc.Stats().EventsFiltered.Get()

			for i := 0; i < 100; i++ {
				require.NoError(t, exec.Command(binNone).Run())
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binA).Run())
			}

			require.GreaterOrEqual(t, waitForExitComm(buf, commA, 15, 10*time.Second), 15)

			matched, _ := exitPoliciesForComm(buf, commA)
			require.Equal(t, []string{"pol-a1", "pol-a2"}, matched,
				"a matching exit must be attributed to both identical-scope policies")

			_, none := exitPoliciesForComm(buf, commNone)
			require.Zero(t, none, "complement exits must be dropped in the kernel")

			require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline)
		})
	})

	// A7 (was Test_PolicyScopeCrossDimensionUnion): OR union across DIMENSIONS (comm vs uid). Each matches its
	// own policy; the complement (neither dimension) is kernel-dropped.
	t.Run("cross dimension union", func(t *testing.T) {
		const uidU = 61234
		commA := fmt.Sprintf("trc7a%d", os.Getpid())
		commU := fmt.Sprintf("trc7u%d", os.Getpid())
		commNone := fmt.Sprintf("trc7n%d", os.Getpid())
		binA := buildCommBinary(t, binDir, commA)
		binU := buildAccessibleCommBinary(t, commU)
		binNone := buildCommBinary(t, binDir, commNone)

		pfs := []testutils.PolicyFileWithID{
			exitPolicyScopes(24, "pol-comm", []string{"comm=" + commA}),
			exitPolicyScopes(25, "pol-uid", []string{fmt.Sprintf("uid=%d", uidU)}),
		}
		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			baseline := trc.Stats().EventsFiltered.Get()

			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binNone).Run()) // neither dimension (root)
			}
			for i := 0; i < 15; i++ {
				runAsUID(t, binU, uidU) // uid dimension
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binA).Run()) // comm dimension
			}

			require.GreaterOrEqual(t, waitForExitComm(buf, commA, 15, 10*time.Second), 15, "comm=A exits emitted")
			require.GreaterOrEqual(t, waitForExitComm(buf, commU, 15, 10*time.Second), 15, "uid=U exits emitted")

			mA, _ := exitPoliciesForComm(buf, commA)
			mU, _ := exitPoliciesForComm(buf, commU)
			_, none := exitPoliciesForComm(buf, commNone)
			require.Equal(t, []string{"pol-comm"}, mA, "comm=A exit attributed to the comm policy only")
			require.Equal(t, []string{"pol-uid"}, mU, "uid=U exit attributed to the uid policy only")
			require.Zero(t, none, "exit matching neither dimension must be dropped in the kernel")
			require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
				"the OR union {comm=A, uid=U} must gate submission in the kernel (complement never reaches userland)")
		})
	})

	// D2 (was Test_PolicyMatchedSubsetAttribution): five policies over three comm scopes; each event is
	// attributed to EXACTLY its matching subset, complement kernel-dropped.
	t.Run("matched subset attribution", func(t *testing.T) {
		commX := fmt.Sprintf("trcd2x%d", os.Getpid())
		commY := fmt.Sprintf("trcd2y%d", os.Getpid())
		commZ := fmt.Sprintf("trcd2z%d", os.Getpid())
		commNone := fmt.Sprintf("trcd2n%d", os.Getpid())
		binX := buildCommBinary(t, binDir, commX)
		binY := buildCommBinary(t, binDir, commY)
		binZ := buildCommBinary(t, binDir, commZ)
		binNone := buildCommBinary(t, binDir, commNone)

		pfs := []testutils.PolicyFileWithID{
			exitScopePolicy(26, "pol-x1", commX),
			exitScopePolicy(27, "pol-x2", commX),
			exitScopePolicy(28, "pol-y1", commY),
			exitScopePolicy(29, "pol-y2", commY),
			exitScopePolicy(30, "pol-z", commZ),
		}
		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			baseline := trc.Stats().EventsFiltered.Get()

			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binNone).Run())
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binX).Run())
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binY).Run())
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binZ).Run())
			}

			require.GreaterOrEqual(t, waitForExitComm(buf, commZ, 15, 10*time.Second), 15)

			mX, _ := exitPoliciesForComm(buf, commX)
			mY, _ := exitPoliciesForComm(buf, commY)
			mZ, _ := exitPoliciesForComm(buf, commZ)
			_, none := exitPoliciesForComm(buf, commNone)

			require.Equal(t, []string{"pol-x1", "pol-x2"}, mX, "X event attributed to exactly the two X policies")
			require.Equal(t, []string{"pol-y1", "pol-y2"}, mY, "Y event attributed to exactly the two Y policies")
			require.Equal(t, []string{"pol-z"}, mZ, "Z event attributed to exactly the one Z policy")
			require.Zero(t, none, "complement dropped in the kernel")
			require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline)
		})
	})

	// A6 (was Test_PolicyScopeKernelPlusDataUserland): kernel comm scope + a USERLAND data filter (exit_code).
	// exit-0 matches both policies; exit-1 is kernel-submitted (comm passed) but excluded from pol-data by the
	// userland exit_code filter, kept by pol-nodata; the comm-complement is kernel-dropped.
	t.Run("kernel plus data userland", func(t *testing.T) {
		commA := fmt.Sprintf("trc6a%d", os.Getpid())
		commNone := fmt.Sprintf("trc6n%d", os.Getpid())
		binExit0 := buildCommBinaryFrom(t, t.TempDir(), commA, "/usr/bin/true")   // comm=A, exit 0
		binExit1 := buildCommBinaryFrom(t, t.TempDir(), commA, "/usr/bin/false")  // comm=A, exit 1
		binNone := buildCommBinaryFrom(t, t.TempDir(), commNone, "/usr/bin/true") // comm complement

		pfs := []testutils.PolicyFileWithID{
			exitScopePolicy(31, "pol-data", commA, "data.exit_code=0"),
			exitScopePolicy(32, "pol-nodata", commA),
		}
		withPolicies(t, trc, buf, pfs, func(t *testing.T) {
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binNone).Run()) // comm complement -> kernel drop
			}
			for i := 0; i < 15; i++ {
				_ = exec.Command(binExit1).Run() // comm=A exit 1
			}
			for i := 0; i < 15; i++ {
				require.NoError(t, exec.Command(binExit0).Run()) // comm=A exit 0
			}

			require.GreaterOrEqual(t, waitForExitCode(buf, commA, 0, 15, 10*time.Second), 15,
				"exit-0 events must be emitted")

			m0, c0 := exitEventsByCode(buf, commA, 0)
			m1, c1 := exitEventsByCode(buf, commA, 1)
			_, cNone := exitPoliciesForComm(buf, commNone)
			t.Logf("A6 diagnostic: emitted commA exit0=%d%v exit1=%d%v; comm-complement emitted=%d", c0, m0, c1, m1, cNone)

			require.Equal(t, []string{"pol-data", "pol-nodata"}, m0, "exit-0 events must match both policies")
			require.Positive(t, c1, "exit-1 events must be emitted via pol-nodata (proves the kernel submitted them)")
			require.Equal(t, []string{"pol-nodata"}, m1,
				"exit-1 events must be excluded from pol-data by the userland exit_code filter, kept by pol-nodata")
			require.Zero(t, cNone, "comm-complement exits must be dropped in the kernel")
		})
	})

	// Was Test_PolicyPerRuleScopeKernelPushdown: a per-rule comm filter on openat (global policy scope) is
	// pushed to the kernel. openat is a SYSCALL event; it can only be selected at runtime because this tracee
	// was started with withRuntimePolicyChanges (Option A pre-loads the syscall dispatchers). Placed last so
	// its probe churn cannot affect the exit-based cases above.
	t.Run("per-rule openat kernel pushdown", func(t *testing.T) {
		commA := fmt.Sprintf("trcpr%d", os.Getpid())
		commNone := fmt.Sprintf("trcpn%d", os.Getpid())
		binA := buildCommBinary(t, binDir, commA)
		binNone := buildCommBinary(t, binDir, commNone)

		withPolicy(t, trc, buf, openatPerRuleCommPolicy(40, "perrule", commA), func(t *testing.T) {
			baseline := trc.Stats().EventsFiltered.Get()

			for i := 0; i < 100; i++ {
				require.NoError(t, exec.Command(binNone).Run()) // complement openats (dropped in kernel)
			}
			for i := 0; i < 20; i++ {
				require.NoError(t, exec.Command(binA).Run()) // matching openats
			}

			deadline := time.Now().Add(10 * time.Second)
			for emittedCountByComm(buf, "openat", commA) == 0 && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
			}
			require.Positive(t, emittedCountByComm(buf, "openat", commA), "matching openat events must be emitted")

			require.Zero(t, trc.Stats().EventsFiltered.Get()-baseline,
				"EventsFiltered moved: complement openat events reached userland, so the per-rule comm scope was not kernel-enforced")
		})
	})
}
