package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	polv1beta1 "github.com/aquasecurity/tracee/pkg/policy/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// syscallerStrategy overrides the trigger strategy for specific syscall EVENTS. Anything not listed
// uses "zero" - all-zero args are enough to fire a syscall-name event (it fires at sys_enter, before
// the call runs), and zero args also defuse most "dangerous" syscalls (a NULL pointer -> EFAULT, a
// zero count/flags -> EINVAL, a zero fd is just stdin). Only the exceptions below need an override.
// This is a curated seed; expanding toward the full syscall-event set is incremental. See the safety
// taxonomy in tests/integration/syscaller/README.md.
//
//	file    - a valid openat-shaped op over a scratch file; also drives derived events
//	          (openat -> security_file_open).
//	invalid - poison args so the call fails at validation (EINVAL/EFAULT/EBADF/EPERM) while its
//	          sys_enter event still fires, run in a fork+watchdog child. Required for exit-class and
//	          blocking syscalls (would kill/hang the tool inline) and used as defense-in-depth for
//	          destructive ones. Pair with --unshare when triggering the destructive entries.
var syscallerStrategy = map[string]string{
	// file: drive the openat -> security_file_open derivation ("open" is x86_64-only).
	"openat": "file",
	"open":   "file",

	// invalid, destructive - reboot / kexec / kernel-module (un)loading / mount / swap / pivot_root.
	// With poison args (and, under --unshare, no host capability) these fail before any effect lands.
	"reboot":          "invalid",
	"kexec_load":      "invalid",
	"kexec_file_load": "invalid",
	"init_module":     "invalid",
	"finit_module":    "invalid",
	"delete_module":   "invalid",
	"mount":           "invalid",
	"pivot_root":      "invalid",
	"swapon":          "invalid",
	"swapoff":         "invalid",
	"unlinkat":        "invalid",

	// invalid, required - exit-class (would end the tool if run inline) and ptrace (zero args =
	// PTRACE_TRACEME, an actual side effect; poison request avoids it). "pause" is x86_64-only and
	// blocks forever; the fork+watchdog kills the child after its timeout.
	"exit":       "invalid",
	"exit_group": "invalid",
	"ptrace":     "invalid",
	"pause":      "invalid",
}

// syscallerSkip lists syscall EVENTS that cannot be triggered as benign, capturable events: they
// replace the process image (exec family), are only valid from a signal frame (rt_sigreturn), or are
// the tool's own fork primitives (clone family). runSyscaller refuses these. (Some are x86_64-only.)
var syscallerSkip = map[string]bool{
	"execve":       true,
	"execveat":     true,
	"clone":        true,
	"clone3":       true,
	"fork":         true,
	"vfork":        true,
	"rt_sigreturn": true,
}

func syscallerStrategyFor(eventName string) string {
	if s, ok := syscallerStrategy[eventName]; ok {
		return s
	}
	return "zero"
}

// runSyscaller runs the Zig syscaller helper: it sets its comm to `comm`, optionally self-isolates
// with --unshare, and triggers each event with that event's strategy (syscallerStrategyFor). Event
// NAMES are resolved here to arch-native syscall numbers (the tool itself does no name translation,
// exactly like formatCmdEvents in event_filters_test.go).
func runSyscaller(t *testing.T, comm string, unshare, forkEach bool, eventNames ...string) {
	t.Helper()
	bin := filepath.Join("..", "..", "dist", "syscaller")
	args := make([]string, 0, len(eventNames)+3)
	if unshare {
		args = append(args, "--unshare")
	}
	if forkEach {
		args = append(args, "--fork-each")
	}
	args = append(args, comm)
	for _, name := range eventNames {
		require.Falsef(t, syscallerSkip[name], "event %q is in the syscaller skip set (cannot be triggered as a benign event)", name)
		def := events.Core.GetDefinitionByName(name)
		require.Falsef(t, def.NotValid(), "no event definition for %q", name)
		args = append(args, fmt.Sprintf("%d:%s", int(def.GetID()), syscallerStrategyFor(name)))
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	require.NoErrorf(t, err, "syscaller %v failed: %s", args, string(out))
}

// eventScopePolicy builds a policy selecting the given events, all scoped to comm=<comm>.
func eventScopePolicy(id int, name, comm string, eventNames ...string) testutils.PolicyFileWithID {
	scope := []string{}
	if comm != "" {
		scope = append(scope, "comm="+comm)
	}
	rules := make([]k8s.Rule, 0, len(eventNames))
	for _, e := range eventNames {
		rules = append(rules, k8s.Rule{Event: e, Filters: []string{}})
	}
	return testutils.PolicyFileWithID{
		Id: id,
		PolicyFile: polv1beta1.PolicyFile{
			Metadata: polv1beta1.Metadata{Name: name},
			Spec: k8s.PolicySpec{
				Scope:          scope,
				DefaultActions: []string{"log"},
				Rules:          rules,
			},
		},
	}
}

// policiesForComm returns the sorted matched-policy set (from the first match) and the count of
// events named `eventName` whose comm is `comm`.
func policiesForComm(buf *testutils.EventBuffer, eventName, comm string) (matched []string, count int) {
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != eventName {
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

// countEventComm counts buffered events named `eventName` whose triggering process comm is `comm`.
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

// waitEventComm polls until at least `want` events named `eventName` with comm `comm` are buffered
// (or timeout), returning the final count.
func waitEventComm(buf *testutils.EventBuffer, eventName, comm string, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		if n := countEventComm(buf, eventName, comm); n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startSyscallerTracee starts a tracee with the given policies applied statically via InitialPolicies
// (main has no runtime policy application), subscribes, and pumps the event stream into an
// EventBuffer. It mirrors the Test_EventFilters harness idiom. The returned stop() unsubscribes,
// cancels the context, and waits for tracee to stop.
func startSyscallerTracee(ctx context.Context, cancel context.CancelFunc, t *testing.T, pols []*policy.Policy) (*testutils.EventBuffer, func()) {
	t.Helper()

	initial := make([]interface{}, 0, len(pols))
	for _, p := range pols {
		initial = append(initial, p)
	}
	cfg := config.Config{
		Capabilities:      &config.CapabilitiesConfig{BypassCaps: true},
		EnrichmentEnabled: false,
	}
	cfg.InitialPolicies = initial

	trc, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err)
	require.NoError(t, testutils.WaitForTraceeStart(trc))

	stream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)

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

	stop := func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("stopping tracee: %v", err)
		}
	}
	return buf, stop
}

// Test_SyscallerTrigger proves the Zig syscaller's new capabilities end-to-end against a live tracee:
//
//  1. --unshare + the `invalid` strategy triggers a BATCH of destructive syscall events (reboot,
//     kernel-module (un)loading, kexec): tracee captures each under the tool's comm, and the host is
//     unharmed - inside a throwaway user/pid/mount/net namespace the process has no host capability
//     and the poison args make each call fail (EPERM/EINVAL), so only the sys_enter events fire.
//  2. the `file` strategy performs a real openat over a scratch file, driving both the openat
//     syscall event AND the derived LSM event security_file_open, under the tool's comm.
//
// Both are scoped by comm - NOT container=new, which keys on a runtime cgroup + enricher that a bare
// unshare does not have.
func Test_SyscallerTrigger(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	// A curated batch of boot / kernel-module syscalls, all triggered via --unshare + the invalid
	// strategy (syscallerStrategy marks each "invalid"). Every entry exists on amd64 and arm64.
	destructive := []string{"reboot", "delete_module", "init_module", "finit_module", "kexec_load"}

	// comm must be <= 15 chars (TASK_COMM_LEN-1) and unique to this run.
	comm := fmt.Sprintf("sctrig%d", os.Getpid()%100000)
	const polName = "syscaller-trigger"
	selected := append(append([]string{}, destructive...), "openat", "security_file_open")
	pols := testutils.NewPolicies([]testutils.PolicyFileWithID{
		eventScopePolicy(1, polName, comm, selected...),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	buf, stop := startSyscallerTracee(ctx, cancel, t, pols)
	defer stop()

	// let the probes attach before triggering
	time.Sleep(2 * time.Second)

	t.Run("unshare+invalid triggers destructive syscall events, host unharmed", func(t *testing.T) {
		runSyscaller(t, comm, true, false, destructive...) // --unshare; each event via the invalid strategy

		for _, ev := range destructive {
			require.GreaterOrEqualf(t, waitEventComm(buf, ev, comm, 1, 15*time.Second), 1,
				"the %s syscall event must be captured under the syscaller comm", ev)
			matched, _ := policiesForComm(buf, ev, comm)
			require.Equalf(t, []string{polName}, matched,
				"the %s event must be attributed to the scoping policy only", ev)
		}
		// Reaching here proves the host was unharmed: each destructive call failed at validation inside
		// a throwaway user/pid/mount/net namespace, so only the sys_enter events fired.
	})

	t.Run("file strategy drives openat and the derived security_file_open", func(t *testing.T) {
		runSyscaller(t, comm, false, false, "openat") // openat:file over a scratch file

		require.GreaterOrEqual(t, waitEventComm(buf, "openat", comm, 1, 15*time.Second), 1,
			"the openat syscall event must be captured under the syscaller comm")
		require.GreaterOrEqual(t, waitEventComm(buf, "security_file_open", comm, 1, 15*time.Second), 1,
			"the file strategy's real open must drive the derived security_file_open event")

		matched, _ := policiesForComm(buf, "security_file_open", comm)
		require.Equal(t, []string{polName}, matched,
			"the derived event must be attributed to the scoping policy only")
	})

	// Negative control. tracee hooks the raw sys_enter tracepoint, which fires for EVERY syscall the
	// process makes - so capture is only meaningful if it is gated by the policy's event selection.
	// getpid is a real, benign syscall this policy does NOT select; triggering it under the same comm
	// must produce no event. If it were captured, the positive assertions above (and the sweep) would
	// be vacuous - capture would be indiscriminate rather than scoped to the selected events.
	t.Run("an unselected syscall is not captured (negative control)", func(t *testing.T) {
		require.NotContains(t, selected, "getpid", "test bug: getpid must not be in the selected set")
		runSyscaller(t, comm, false, false, "getpid") // triggered, but not selected by the policy

		// Give any (erroneous) getpid event time to arrive; waitEventComm returns as soon as one shows
		// up, or 0 after the timeout. It must stay 0.
		require.Zero(t, waitEventComm(buf, "getpid", comm, 1, 5*time.Second),
			"getpid is not selected by the policy, so it must not be captured under the comm")
	})
}

// syscallerArchSpecific lists table keys that exist on only some arches, so the drift guard tolerates
// their absence on the arch under test (x86_64 has these; arm64 uses openat/clone/... instead).
var syscallerArchSpecific = map[string]bool{
	"open":  true,
	"fork":  true,
	"vfork": true,
	"pause": true,
}

// Test_SyscallerTableDrift keeps the strategy/skip tables aligned with tracee's event set (no root
// needed), so a rename/removal in tracee, or a typo, is caught here instead of silently
// misclassifying a syscall.
func Test_SyscallerTableDrift(t *testing.T) {
	// A strategy key is actively used to pick a syscall's trigger args, so each MUST be a real syscall
	// event on this arch (arch-specific names excepted) - a stale or typo'd key would misclassify.
	for name := range syscallerStrategy {
		if syscallerArchSpecific[name] {
			continue
		}
		def := events.Core.GetDefinitionByName(name)
		require.Falsef(t, def.NotValid(),
			"syscallerStrategy references %q, not a tracee event on this arch (typo, or tracee renamed/removed it)", name)
		require.Truef(t, def.IsSyscall(), "syscallerStrategy references %q, which is not a syscall event", name)
	}
	// skip is a deny-list: it may name syscalls tracee does not define yet (e.g. clone3), so absence
	// is fine. But if a skip entry DOES resolve it must be a syscall, and a name must never be in both
	// tables (a contradiction).
	for name := range syscallerSkip {
		if def := events.Core.GetDefinitionByName(name); !def.NotValid() {
			require.Truef(t, def.IsSyscall(), "syscallerSkip references %q, which is not a syscall event", name)
		}
		_, dup := syscallerStrategy[name]
		require.Falsef(t, dup, "%q is in both syscallerStrategy and syscallerSkip", name)
	}
}

// nativeSyscalls returns the arch-native syscall events the coverage sweep triggers. It is derived
// from events.Core, so it tracks tracee automatically - a PR adding syscall definitions (e.g. #5331)
// is covered with no edit here. Two filters keep it to the set whose event ID is a real native
// syscall number that runSyscaller can trigger:
//
//   - arch: skip the Unsupported sentinel range (a syscall absent on this arch, e.g. open on arm64,
//     gets an ID >= events.Unsupported) and the "32bit_unique" set (i386-only syscalls tracee
//     defines for tracing 32-bit processes - socketcall, *16, *64, *_time32, ... - not native to a
//     64-bit process, so their event ID is not a native syscall number here);
//   - resolvable: only names runSyscaller can turn into a number via GetDefinitionByName.
func nativeSyscalls() []string {
	var names []string
	for _, def := range events.Core.GetDefinitions() {
		if !def.IsSyscall() {
			continue
		}
		if def.GetID() >= events.Unsupported || slices.Contains(def.GetSets(), "32bit_unique") {
			continue // not native to this arch
		}
		n := def.GetName()
		if n == "" || syscallerSkip[n] {
			continue
		}
		if events.Core.GetDefinitionByName(n).NotValid() {
			continue // only names runSyscaller can resolve
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Test_SyscallerSweep is the self-aligning coverage test. It triggers EVERY arch-native syscall
// tracee defines (minus the skip set) through the syscaller under --unshare --fork-each, and asserts
// each is captured under the tool's comm. --fork-each isolates every call in a throwaway child so a
// side-effecting syscall cannot poison the rest, and the user namespace strips host privilege.
//
// It asserts capture for ALL of them - not a kernel-filtered subset - because tracee hooks the raw
// sys_enter tracepoint, which fires on syscall ENTRY for every number in the arch's table (a real
// handler, a stubbed sys_ni_syscall, or an unassigned slot alike), before the kernel resolves an
// unknown call to ENOSYS. So "does the running kernel implement it" is not a capture gap: every
// native syscall tracee knows is captured when triggered (an obsolete one like create_module fires
// its event just the same). A syscall genuinely un-triggerable this way goes in syscallerSkip.
//
// It runs in the integration suite - the whole table is triggered in one short-lived tracee. When
// tracee gains syscalls this covers them with no edit; the failure names exactly what was missed.
func Test_SyscallerSweep(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	native := nativeSyscalls()
	require.NotEmpty(t, native, "no native syscall events found in events.Core")

	comm := fmt.Sprintf("scswp%d", os.Getpid()%100000)
	const polName = "syscaller-sweep"
	pols := testutils.NewPolicies([]testutils.PolicyFileWithID{
		eventScopePolicy(1, polName, comm, native...),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	buf, stop := startSyscallerTracee(ctx, cancel, t, pols)
	defer stop()

	time.Sleep(2 * time.Second)

	runSyscaller(t, comm, true, true, native...) // --unshare --fork-each; the whole native table at once

	// Wait until the captured distinct-event set under the comm stops growing (or timeout).
	seen := make(map[string]bool, len(native))
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, e := range buf.GetCopy() {
			if e == nil || e.Workload == nil || e.Workload.Process == nil ||
				e.Workload.Process.Thread == nil || e.Workload.Process.Thread.Name != comm {
				continue
			}
			seen[e.Name] = true
		}
		if len(seen) >= len(native) || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	var notCaptured []string
	for _, n := range native {
		if !seen[n] {
			notCaptured = append(notCaptured, n)
		}
	}

	t.Logf("sweep: %d/%d native syscalls captured under comm %q", len(native)-len(notCaptured), len(native), comm)
	// Name (with id) any that were not captured - the actual problem set, listed on every run before
	// the assertion so it is visible whether or not the test fails.
	for _, n := range notCaptured {
		t.Logf("  not-captured: %-28s id=%d", n, int(events.Core.GetDefinitionByName(n).GetID()))
	}

	require.Emptyf(t, notCaptured,
		"%d/%d native syscalls not captured (add any genuinely un-triggerable ones to syscallerSkip): %v",
		len(notCaptured), len(native), notCaptured)
}
