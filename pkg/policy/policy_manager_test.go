package policy

import (
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
		func(id events.ID) events.Dependencies {
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
		func(id events.ID) events.Dependencies {
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
		func(id events.ID) events.Dependencies {
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
		func(id events.ID) events.Dependencies {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	// Create two policies with different filters and rules.
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

	// Add the policies to the PolicyManager.
	err = pm.AddPolicy(p1)
	require.NoError(t, err)
	err = pm.AddPolicy(p2)
	require.NoError(t, err)

	// 1. Modify p1's filters and rules *after* adding to the manager.
	err = p1.UIDFilter.Parse("=0") // Change UID filter
	require.NoError(t, err)
	p1.Rules[events.SecurityFileOpen] = RuleData{EventID: events.SecurityFileOpen} // Add a new rule

	// 2. Verify that p2's filters and rules are unaffected.
	p2Fetched, err := pm.LookupPolicyByName("policy2")
	require.NoError(t, err)
	require.True(t, p2Fetched.PIDFilter.Enabled())                   // PID filter should be enabled
	require.False(t, p2Fetched.UIDFilter.Enabled())                  // UID filter should be disabled
	require.NotContains(t, p2Fetched.Rules, events.SecurityFileOpen) // p2 should not have the new rule

	// 3. Modify p2's filters and rules *after* adding to the manager.
	err = p2.CommFilter.Parse("=bash") // Add a comm filter
	require.NoError(t, err)
	delete(p2.Rules, events.SchedProcessExec) // Remove a rule

	// 4. Verify that p1's filters and rules are unaffected.
	p1Fetched, err := pm.LookupPolicyByName("policy1")
	require.NoError(t, err)
	require.True(t, p1Fetched.UIDFilter.Enabled())                   // UID filter should be enabled
	require.False(t, p1Fetched.CommFilter.Enabled())                 // Comm filter should be disabled
	require.NotContains(t, p1Fetched.Rules, events.SchedProcessExec) // p1 should not have lost it's rule

	// 5. Remove p1 from the manager
	err = pm.RemovePolicy("policy1")
	require.NoError(t, err)

	// 6. Verify that p2 is still present and its rules are intact
	_, err = pm.LookupPolicyByName("policy1")
	require.ErrorIs(t, err, PolicyNotFoundByNameError("policy1")) // p1 should not be found
	p2Fetched, err = pm.LookupPolicyByName("policy2")
	require.NoError(t, err)
	require.True(t, p2Fetched.PIDFilter.Enabled())                // p2's PID filter should be enabled
	require.True(t, p2Fetched.CommFilter.Enabled())               // p2's Comm filter should be enabled
	require.Contains(t, p2Fetched.Rules, events.SchedProcessExec) // p2 should still have its original rule
}
