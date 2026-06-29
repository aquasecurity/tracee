package integration

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// These are e2e integration tests: they start a real Tracee (BPF loaded) and therefore need
// root. They cover the `tree` and `follow` scope filters under the matched-rules model.
//
//   - tree   : programmatic policy (the root PID is only known at runtime), driven by a small
//              signal-synced C helper (testdata/tree_tester.c) so the descendant is spawned
//              AFTER tracee starts — exercising fork-time membership propagation.
//   - follow : loaded from a real policy YAML fixture (testdata/policies/follow_bash.yaml),
//              showcasing the YAML-loading harness (testutils.NewPoliciesFromPaths).

// runWithPolicies starts tracee with the given policies, runs workload (after tracee is up),
// lets events settle, and returns the collected events.
func runWithPolicies(t *testing.T, policies []*policy.Policy, settle time.Duration, workload func(t *testing.T)) *testutils.EventBuffer {
	t.Helper()

	traceeConfig := config.Config{
		Capabilities:      &config.CapabilitiesConfig{BypassCaps: true},
		EnrichmentEnabled: false,
	}
	initial := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initial = append(initial, p)
	}
	traceeConfig.InitialPolicies = initial

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, err := testutils.StartTracee(ctx, t, traceeConfig, nil, nil)
	require.NoError(t, err)
	require.NoError(t, testutils.WaitForTraceeStart(trc))

	stream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)
	defer trc.Unsubscribe(stream)

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

	workload(t)
	time.Sleep(settle) // let the workload's events flow into the buffer

	cancel()
	_ = testutils.WaitForTraceeStop(trc)
	return buf
}

// hasMatchedEvent reports whether the buffer contains an event with the given name, process
// comm (skip with ""), and matched policy name (skip with "").
func hasMatchedEvent(buf *testutils.EventBuffer, eventName, comm, policyName string) bool {
	for _, e := range buf.GetCopy() {
		if e.Name != eventName {
			continue
		}
		if comm != "" {
			if e.Workload == nil || e.Workload.Process == nil || e.Workload.Process.Thread == nil ||
				e.Workload.Process.Thread.Name != comm {
				continue
			}
		}
		if policyName != "" {
			if e.Policies == nil {
				continue
			}
			matched := false
			for _, p := range e.Policies.Matched {
				if p == policyName {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return true
	}
	return false
}

func execEventName() string {
	return events.Core.GetDefinitionByID(events.SchedProcessExec).GetName()
}

// treeProgrammaticPolicy builds a single policy (named name) with the given scope filters and
// a sched_process_exec rule. tree filters carry a runtime PID, so they cannot live in a static
// YAML fixture — they are injected here, mirroring how mntns/pidns are injected elsewhere.
func treeProgrammaticPolicy(name string, scopes ...string) []*policy.Policy {
	pf := testutils.PolicyFileWithID{
		PolicyFile: v1beta1.PolicyFile{
			Metadata: v1beta1.Metadata{Name: name},
			Spec: k8s.PolicySpec{
				Scope:          scopes,
				DefaultActions: []string{"log"},
				Rules:          []k8s.Rule{{Event: execEventName()}},
			},
		},
	}
	return testutils.NewPolicies([]testutils.PolicyFileWithID{pf})
}

// buildTreeTester compiles testdata/tree_tester.c and returns the binary path.
func buildTreeTester(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc not available: %v", err)
	}
	out := filepath.Join(t.TempDir(), "tree_tester")
	build := exec.Command("gcc", "-o", out, "testdata/tree_tester.c")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile tree_tester.c: %v\n%s", err, output)
	}
	return out
}

// startTreeTester starts the helper and waits for its "READY" line (signal handler installed),
// returning the running command and its host PID.
func startTreeTester(t *testing.T, bin string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	line, err := bufio.NewReader(stdout).ReadString('\n') // "READY <pid>"
	require.NoError(t, err)
	require.Truef(t, len(line) > 0, "unexpected READY line %q", line)
	return cmd
}

func TestTreeScopeFilter(t *testing.T) {
	testutils.AssureIsRoot(t)
	bin := buildTreeTester(t)

	spawnAfterStart := func(cmd *exec.Cmd) func(t *testing.T) {
		return func(t *testing.T) {
			require.NoError(t, cmd.Process.Signal(syscall.SIGUSR1)) // tell the helper to fork `sleep`
			time.Sleep(1 * time.Second)                             // let it fork+exec
		}
	}

	t.Run("include subtree (tree=)", func(t *testing.T) {
		cmd := startTreeTester(t, bin)
		defer func() { _ = cmd.Process.Kill() }()

		pols := treeProgrammaticPolicy("tree-include",
			"comm=sleep", fmt.Sprintf("tree=%d", cmd.Process.Pid))
		buf := runWithPolicies(t, pols, 3*time.Second, spawnAfterStart(cmd))

		assert.True(t, hasMatchedEvent(buf, execEventName(), "sleep", "tree-include"),
			"sleep is a descendant of the tree root and must be captured")
	})

	t.Run("exclude subtree (tree!=)", func(t *testing.T) {
		cmd := startTreeTester(t, bin)
		defer func() { _ = cmd.Process.Kill() }()

		pols := treeProgrammaticPolicy("tree-exclude",
			"comm=sleep", fmt.Sprintf("tree!=%d", cmd.Process.Pid))
		buf := runWithPolicies(t, pols, 3*time.Second, spawnAfterStart(cmd))

		assert.False(t, hasMatchedEvent(buf, execEventName(), "sleep", "tree-exclude"),
			"sleep under the excluded subtree must NOT be captured")
	})
}

func TestFollowScopeFilter(t *testing.T) {
	testutils.AssureIsRoot(t)

	pols, err := testutils.NewPoliciesFromPaths([]string{"testdata/policies/follow_bash.yaml"})
	require.NoError(t, err)

	buf := runWithPolicies(t, pols, 3*time.Second, func(t *testing.T) {
		// bash matches comm=bash and is "followed"; the sleep it spawns is a descendant and
		// must be captured via follow even though comm=sleep does not match the scope.
		require.NoError(t, exec.Command("bash", "-c", "sleep 1").Run())
		time.Sleep(500 * time.Millisecond)
	})

	assert.True(t, hasMatchedEvent(buf, execEventName(), "bash", "follow-bash"),
		"bash itself must be captured (matches comm=bash)")
	assert.True(t, hasMatchedEvent(buf, execEventName(), "sleep", "follow-bash"),
		"sleep spawned by bash must be captured via follow")
}
