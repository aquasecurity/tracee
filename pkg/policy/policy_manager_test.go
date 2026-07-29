package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
)

func TestPolicyManagerEnableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.False(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))
}

func TestPolicyManagerDisableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))

	policyManager.DisableEvent(events.SecurityBPF)
	policyManager.DisableEvent(events.SecurityFileOpen)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))
}

func TestPolicyManagerEnableAndDisableEventConcurrent(t *testing.T) {
	t.Parallel()

	eventsToEnable := []events.ID{
		events.SecurityBPF,
		events.SchedGetPriorityMax,
		events.SchedProcessExec,
		events.SchedProcessExit,
		events.Ptrace,
	}

	eventsToDisable := []events.ID{
		events.SecurityBPFMap,
		events.Openat2,
		events.SchedProcessFork,
		events.MagicWrite,
		events.FileModification,
	}

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	// activate events
	for _, e := range eventsToDisable {
		policyManager.EnableEvent(e)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			for _, e := range eventsToEnable {
				policyManager.EnableEvent(e)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			for _, e := range eventsToDisable {
				policyManager.DisableEvent(e)
			}
		}
	}()

	wg.Wait()

	for i := 0; i < 100; i++ {
		for _, e := range eventsToEnable {
			assert.True(t, policyManager.IsEventEnabled(e))
		}
		for _, e := range eventsToDisable {
			assert.False(t, policyManager.IsEventEnabled(e))
		}
	}
}

func TestPolicyManagerIndependentPolicies(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	// Create two policies with different filters and rules
	p1 := NewPolicy()
	p1.Name = "policy1"
	err = p1.UIDFilter.Parse(">=1000")
	require.NoError(t, err)
	p1.Rules[events.SchedProcessFork] = RuleData{EventID: events.SchedProcessFork}

	p2 := NewPolicy()
	p2.Name = "policy2"
	err = p2.PIDFilter.Parse("=1")
	require.NoError(t, err)
	p2.Rules[events.SchedProcessExec] = RuleData{EventID: events.SchedProcessExec}

	// Test policy addition
	err = pm.AddPolicy(p1)
	require.NoError(t, err)
	err = pm.AddPolicy(p2)
	require.NoError(t, err)

	// Verify policies are independent
	p2Fetched, err := pm.LookupPolicyByName("policy2")
	require.NoError(t, err)
	require.True(t, p2Fetched.PIDFilter.Enabled())
	require.False(t, p2Fetched.UIDFilter.Enabled())
	require.NotContains(t, p2Fetched.Rules, events.SchedProcessFork)

	// Test policy removal
	err = pm.RemovePolicy("policy1")
	require.NoError(t, err)

	// Verify policy1 removed and policy2 unaffected
	_, err = pm.LookupPolicyByName("policy1")
	expectedErr := &policyError{msg: fmt.Sprintf("policy [%s] not found", "policy1")}
	require.ErrorIs(t, err, expectedErr)

	p2Fetched, err = pm.LookupPolicyByName("policy2")
	require.NoError(t, err)
	require.True(t, p2Fetched.PIDFilter.Enabled())
	require.Contains(t, p2Fetched.Rules, events.SchedProcessExec)
}

// TestPolicyManagerUpdatePolicy verifies UpdatePolicy atomically replaces a policy by name: its filters and
// event set change, other policies are unaffected, dropped events lose the policy's rule, and error cases
// (nil, unknown name) are rejected.
func TestPolicyManagerUpdatePolicy(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	// original "p" selects sched_process_fork with uid>=1000; independent "other" selects sched_process_exec.
	p := NewPolicy()
	p.Name = "p"
	require.NoError(t, p.UIDFilter.Parse(">=1000"))
	p.Rules[events.SchedProcessFork] = RuleData{EventID: events.SchedProcessFork}
	require.NoError(t, pm.AddPolicy(p))

	other := NewPolicy()
	other.Name = "other"
	other.Rules[events.SchedProcessExec] = RuleData{EventID: events.SchedProcessExec}
	require.NoError(t, pm.AddPolicy(other))

	// update "p": now selects sched_process_exec with pid=1 (drops fork + uid, adds pid + exec).
	upd := NewPolicy()
	upd.Name = "p"
	require.NoError(t, upd.PIDFilter.Parse("=1"))
	upd.Rules[events.SchedProcessExec] = RuleData{EventID: events.SchedProcessExec}
	require.NoError(t, pm.UpdatePolicy(upd))

	// the policy definition is replaced
	got, err := pm.LookupPolicyByName("p")
	require.NoError(t, err)
	require.True(t, got.PIDFilter.Enabled())
	require.False(t, got.UIDFilter.Enabled())
	require.Contains(t, got.Rules, events.SchedProcessExec)
	require.NotContains(t, got.Rules, events.SchedProcessFork)

	// the rule maps reflect the change: exec now carries a "p" rule; fork no longer does.
	hasPolicyRule := func(eventID events.ID, name string) bool {
		er, ok := pm.rules[eventID]
		if !ok {
			return false
		}
		for _, r := range er.Rules {
			if r.Policy != nil && r.Policy.Name == name {
				return true
			}
		}
		return false
	}
	require.True(t, hasPolicyRule(events.SchedProcessExec, "p"), "updated p must now match sched_process_exec")
	require.False(t, hasPolicyRule(events.SchedProcessFork, "p"), "updated p must no longer match sched_process_fork")

	// "other" is unaffected, and still shares sched_process_exec.
	otherGot, err := pm.LookupPolicyByName("other")
	require.NoError(t, err)
	require.Contains(t, otherGot.Rules, events.SchedProcessExec)
	require.True(t, hasPolicyRule(events.SchedProcessExec, "other"), "other must still match sched_process_exec")

	// error cases
	require.Error(t, pm.UpdatePolicy(nil))
	missing := NewPolicy()
	missing.Name = "nope"
	missing.Rules[events.SchedProcessExec] = RuleData{EventID: events.SchedProcessExec}
	require.Error(t, pm.UpdatePolicy(missing))
}

// TestPolicyManagerSnapshotConcurrentReadWrite hammers the lock-free read accessors from many goroutines
// while a writer churns policies (add/update/remove) and event toggles. Its purpose is to be run under
// -race: the atomically-published immutable snapshot must let readers proceed without locking and without
// ever observing a torn update (a concurrent map read/write, or half-applied rules).
func TestPolicyManagerSnapshotConcurrentReadWrite(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	// A permanent policy so a known event is always selected.
	base := NewPolicy()
	base.Name = "base"
	base.Rules[events.Openat] = RuleData{EventID: events.Openat}
	require.NoError(t, pm.AddPolicy(base))

	const (
		readers = 8
		iters   = 400
	)
	probe := []events.ID{events.Openat, events.SchedProcessExec, events.Close}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, id := range probe {
					_ = pm.GetUserlandRules(id)
					_ = pm.GetAllRulesBitmap(id)
					_ = pm.HasOverflowRules(id)
					_ = pm.GetRulesCount(id)
					_ = pm.GetContainerFilteredRulesBitmap(id)
					_ = pm.GetDisabledRules(id)
					_ = pm.IsEventSelected(id)
					_ = pm.ShouldEmitEvent(id)
					_ = pm.GetFilterMaps()
					_ = pm.GetMatchedRulesInfo(id, []uint64{0b1})
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for n := 0; n < iters; n++ {
			p := NewPolicy()
			p.Name = "churn"
			p.Rules[events.SchedProcessExec] = RuleData{EventID: events.SchedProcessExec}
			_ = pm.AddPolicy(p)

			upd := NewPolicy()
			upd.Name = "churn"
			upd.Rules[events.Close] = RuleData{EventID: events.Close}
			_ = pm.UpdatePolicy(upd)

			pm.DisableEvent(events.Openat)
			pm.EnableEvent(events.Openat)
			_ = pm.RemovePolicy("churn")
		}
	}()

	wg.Wait()

	// The permanent policy's event is still consistently selected after all the churn.
	require.True(t, pm.IsEventSelected(events.Openat))
}

// TestPolicyManagerListPolicyNames verifies ListPolicyNames returns user policies sorted, excluding the
// internal bootstrap policy, and reflects add/remove.
func TestPolicyManagerListPolicyNames(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	require.Empty(t, pm.ListPolicyNames(), "only the bootstrap policy exists, which is excluded")

	a := NewPolicy()
	a.Name = "aaa"
	a.Rules[events.Openat] = RuleData{EventID: events.Openat}
	b := NewPolicy()
	b.Name = "bbb"
	b.Rules[events.Close] = RuleData{EventID: events.Close}
	require.NoError(t, pm.AddPolicy(b))
	require.NoError(t, pm.AddPolicy(a))

	require.Equal(t, []string{"aaa", "bbb"}, pm.ListPolicyNames(), "sorted, bootstrap excluded")

	require.NoError(t, pm.RemovePolicy("aaa"))
	require.Equal(t, []string{"bbb"}, pm.ListPolicyNames())
}
