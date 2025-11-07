package policy

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
)

func TestPolicyManagerEnableRule(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	assert.False(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	err = policyManager.EnableRule(1, events.SecurityBPF)
	assert.NoError(t, err)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	err = policyManager.EnableRule(2, events.SecurityBPF)
	assert.NoError(t, err)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	err = policyManager.EnableRule(-1, events.SecurityBPF)
	assert.Error(t, err)
}

func TestPolicyManagerDisableRule(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	err = policyManager.EnableRule(1, events.SecurityBPF)
	assert.NoError(t, err)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	err = policyManager.DisableRule(1, events.SecurityBPF)
	assert.NoError(t, err)

	assert.False(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	err = policyManager.DisableRule(-1, events.SecurityBPF)
	assert.Error(t, err)
}

func TestPolicyManagerEnableAndDisableRuleConcurrent(t *testing.T) {
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

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		for i := 0; i < PolicyMax; i++ {
			for _, e := range eventsToEnable {
				policyManager.EnableRule(i, e)
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for i := 0; i < PolicyMax; i++ {
			for _, e := range eventsToDisable {
				policyManager.DisableRule(i, e)
			}
		}
		wg.Done()
	}()

	wg.Wait()

	for i := 0; i < PolicyMax; i++ {
		for _, e := range eventsToEnable {
			assert.True(t, policyManager.IsRuleEnabled(PolicyAll, e))
		}
		for _, e := range eventsToDisable {
			assert.False(t, policyManager.IsRuleEnabled(PolicyAll, e))
		}
	}
}

func TestPolicyManagerEnableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	assert.False(t, policyManager.isEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.isEventEnabled(events.SecurityFileOpen))
	assert.False(t, policyManager.isEventEnabled(events.SecuritySocketAccept))

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.isEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.isEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.isEventEnabled(events.SecuritySocketAccept))
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
		for i := 0; i < PolicyMax; i++ {
			for _, e := range eventsToEnable {
				policyManager.EnableEvent(e)
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for i := 0; i < PolicyMax; i++ {
			for _, e := range eventsToDisable {
				policyManager.DisableEvent(e)
			}
		}
		wg.Done()
	}()

	wg.Wait()

	for i := 0; i < PolicyMax; i++ {
		for _, e := range eventsToEnable {
			assert.True(t, policyManager.IsEventEnabled(e))
		}
		for _, e := range eventsToDisable {
			assert.False(t, policyManager.IsEventEnabled(e))
		}
	}
}

func TestEnableRuleAlsoEnableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))

	policyManager.EnableRule(1, events.SecurityBPF)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
}

func TestDisableRuleAlsoEnableEvent(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))

	policyManager.DisableRule(1, events.SecurityFileOpen)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
}

func TestPolicyManagerIsEnabled(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager)
	assert.NoError(t, err)

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	assert.False(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableRule(1, events.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableRule(2, events.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.DisableEvent(events.SecurityBPF)

	assert.False(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableEvent(events.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))
}

func TestPolicyManagerIsEventFilteredByScope(t *testing.T) {
	t.Parallel()

	// Create a policy with scope filters
	// SecurityBPF on container context and SecurityFileOpen on pid context
	policy1 := NewPolicy()
	policy1.ID = 0
	policy1.Name = "policy-with-container-scope"

	// Create a rule with container scope filter
	ruleData1 := RuleData{
		EventID:     events.SecurityBPF,
		ScopeFilter: filters.NewScopeFilter(),
	}
	err := ruleData1.ScopeFilter.Parse(filters.ScopeContainer, "")
	assert.NoError(t, err)
	policy1.Rules[events.SecurityBPF] = ruleData1

	// Create a rule with pid scope filter
	ruleData2 := RuleData{
		EventID:     events.SecurityFileOpen,
		ScopeFilter: filters.NewScopeFilter(),
	}
	err = ruleData2.ScopeFilter.Parse(filters.ScopePID, "=1234")
	assert.NoError(t, err)
	policy1.Rules[events.SecurityFileOpen] = ruleData2

	//

	// Create another policy with host scope filter
	// SecurityBPF on host context
	policy2 := NewPolicy()
	policy2.ID = 1
	policy2.Name = "policy-with-host-scope"

	ruleData3 := RuleData{
		EventID:     events.SecurityBPF,
		ScopeFilter: filters.NewScopeFilter(),
	}
	err = ruleData3.ScopeFilter.Parse(filters.ScopeHost, "")
	assert.NoError(t, err)
	policy2.Rules[events.SecurityBPF] = ruleData3

	//

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	policyManager, err := NewManager(ManagerConfig{}, depsManager, policy1, policy2)
	assert.NoError(t, err)

	// Test container scope filtering
	assert.True(t, policyManager.IsEventFilteredByScope(events.SecurityBPF, filters.ScopeContainer))

	// Test host scope filtering
	assert.True(t, policyManager.IsEventFilteredByScope(events.SecurityBPF, filters.ScopeHost))

	// Test pid scope filtering
	assert.True(t, policyManager.IsEventFilteredByScope(events.SecurityFileOpen, filters.ScopePID))

	// Test scope NOT enabled for event
	assert.False(t, policyManager.IsEventFilteredByScope(events.SecurityFileOpen, filters.ScopeContainer))

	// Test host scope NOT enabled for event
	assert.False(t, policyManager.IsEventFilteredByScope(events.SecurityFileOpen, filters.ScopeHost))

	// Test event NOT in any policy
	assert.False(t, policyManager.IsEventFilteredByScope(events.SecuritySocketAccept, filters.ScopeContainer))

	// Test unknown scope name
	assert.False(t, policyManager.IsEventFilteredByScope(events.SecurityBPF, filters.ScopeName("unknownScope")))
}
