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
