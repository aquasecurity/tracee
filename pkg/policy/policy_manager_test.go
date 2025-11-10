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

// Helper functions for TestPolicyManagerIsContainerFilterSetOnEvent

func createPolicyWithContFilter(t *testing.T, id int, name string, eventID events.ID, filterValue string) *Policy {
	t.Helper()
	p := NewPolicy()
	p.ID = id
	p.Name = name
	p.Rules[eventID] = RuleData{
		EventID:     eventID,
		DataFilter:  filters.NewDataFilter(),
		RetFilter:   filters.NewIntFilter(),
		ScopeFilter: filters.NewScopeFilter(),
	}
	if err := p.ContFilter.Parse(filterValue); err != nil {
		t.Fatalf("failed to parse ContFilter: %v", err)
	}

	return p
}

func createPolicyWithNewContFilter(t *testing.T, id int, name string, eventID events.ID, filterValue string) *Policy {
	t.Helper()
	p := NewPolicy()
	p.ID = id
	p.Name = name
	p.Rules[eventID] = RuleData{
		EventID:     eventID,
		DataFilter:  filters.NewDataFilter(),
		RetFilter:   filters.NewIntFilter(),
		ScopeFilter: filters.NewScopeFilter(),
	}
	if err := p.NewContFilter.Parse(filterValue); err != nil {
		t.Fatalf("failed to parse NewContFilter: %v", err)
	}

	return p
}

func createPolicyWithContIDFilter(t *testing.T, id int, name string, eventID events.ID, filterValue string) *Policy {
	t.Helper()
	p := NewPolicy()
	p.ID = id
	p.Name = name
	p.Rules[eventID] = RuleData{
		EventID:     eventID,
		DataFilter:  filters.NewDataFilter(),
		RetFilter:   filters.NewIntFilter(),
		ScopeFilter: filters.NewScopeFilter(),
	}
	if err := p.ContIDFilter.Parse(filterValue); err != nil {
		t.Fatalf("failed to parse ContIDFilter: %v", err)
	}

	return p
}

func createPolicyWithMultipleFilters(t *testing.T, id int, name string, eventID events.ID, contFilter, newContFilter, contIDFilter string) *Policy {
	t.Helper()
	p := NewPolicy()
	p.ID = id
	p.Name = name
	p.Rules[eventID] = RuleData{
		EventID:     eventID,
		DataFilter:  filters.NewDataFilter(),
		RetFilter:   filters.NewIntFilter(),
		ScopeFilter: filters.NewScopeFilter(),
	}
	if contFilter != "" {
		if err := p.ContFilter.Parse(contFilter); err != nil {
			t.Fatalf("failed to parse ContFilter: %v", err)
		}
	}
	if newContFilter != "" {
		if err := p.NewContFilter.Parse(newContFilter); err != nil {
			t.Fatalf("failed to parse NewContFilter: %v", err)
		}
	}
	if contIDFilter != "" {
		if err := p.ContIDFilter.Parse(contIDFilter); err != nil {
			t.Fatalf("failed to parse ContIDFilter: %v", err)
		}
	}

	return p
}

func createPolicyNoFilters(t *testing.T, id int, name string, eventID events.ID) *Policy {
	t.Helper()
	p := NewPolicy()
	p.ID = id
	p.Name = name
	p.Rules[eventID] = RuleData{
		EventID:     eventID,
		DataFilter:  filters.NewDataFilter(),
		RetFilter:   filters.NewIntFilter(),
		ScopeFilter: filters.NewScopeFilter(),
	}

	return p
}

func TestPolicyManagerIsContainerFilterSetOnEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		createPolicies  func(t *testing.T) []*Policy
		eventID         events.ID
		expectHost      bool
		expectContainer bool
	}{
		{
			name: "no policies",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: false,
		},
		{
			name: "policy with no container filter",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyNoFilters(t, 0, "no-container-filter", events.SecurityBPF),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: false,
		},
		{
			name: "single policy with container=true",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "container-only", events.SecurityBPF, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "single policy with container=false (host only)",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "host-only", events.SecurityBPF, "=false"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: false,
		},
		{
			name: "multiple policies with both container=true and container=false",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "host-only", events.SecurityBPF, "=false"),
					createPolicyWithContFilter(t, 1, "container-only", events.SecurityBPF, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
		{
			name: "event not in any policy",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "container-filter", events.SecurityFileOpen, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: false,
		},
		{
			name: "multiple policies, only one has the event with container filter",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "policy-without-event", events.SecurityFileOpen, "=false"),
					createPolicyWithContFilter(t, 1, "policy-with-event", events.SecurityBPF, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "policy with event but no container filter enabled",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyNoFilters(t, 0, "no-filter-enabled", events.SecurityBPF),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: false,
		},
		{
			name: "multiple policies with same event, different filters",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "container-policy-1", events.SecurityBPF, "=true"),
					createPolicyWithContFilter(t, 1, "container-policy-2", events.SecurityBPF, "=true"),
					createPolicyNoFilters(t, 2, "no-filter", events.SecurityBPF),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "single policy with new-container=true",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithNewContFilter(t, 0, "new-container-only", events.SecurityBPF, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "single policy with new-container=false",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithNewContFilter(t, 0, "not-new-container", events.SecurityBPF, "=false"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
		{
			name: "policy with container=true and new-container=true",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithMultipleFilters(t, 0, "container-and-new", events.SecurityBPF, "=true", "=true", ""),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "policy with container=false and new-container=true",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithMultipleFilters(t, 0, "host-and-new-container", events.SecurityBPF, "=false", "=true", ""),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
		{
			name: "mixed policies with ContFilter and NewContFilter",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "container-only", events.SecurityBPF, "=true"),
					createPolicyWithNewContFilter(t, 1, "new-container-only", events.SecurityBPF, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "single policy with container ID filter",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContIDFilter(t, 0, "container-id-filter", events.SecurityBPF, "=abc123"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "policy with container ID filter and container=false",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithMultipleFilters(t, 0, "container-id-and-host", events.SecurityBPF, "=false", "", "=abc123,def456"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
		{
			name: "policy with container ID filter and new-container=true",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithMultipleFilters(t, 0, "container-id-and-new", events.SecurityBPF, "", "=true", "=abc123"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "mixed policies with different filter types including ContIDFilter",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "host-only", events.SecurityBPF, "=false"),
					createPolicyWithContIDFilter(t, 1, "specific-container", events.SecurityBPF, "=abc123"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
		{
			name: "policy with all three container filter types",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithMultipleFilters(t, 0, "all-filters", events.SecurityBPF, "=true", "=true", "=abc123"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "edge case: contradictory filters - container=false AND container-id=X",
			createPolicies: func(t *testing.T) []*Policy {
				// This combination is contradictory:
				// - container=false means "only host"
				// - container-id=X means "only this container"
				// When ANDed together, this will match nothing in actual filtering.
				// But this method reports both scopes are referenced.
				// NOTE: This CAN happen via CLI: -s not-container -s container=abc123
				// or YAML: scope: [not-container, container=abc123]
				// parseScopeFilters() calls Parse() on each scope flag sequentially.
				return []*Policy{
					createPolicyWithMultipleFilters(t, 0, "contradictory-filters", events.SecurityBPF, "=false", "", "=abc123"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
		{
			name: "edge case: both container and not-container in same policy",
			createPolicies: func(t *testing.T) []*Policy {
				// Simulates: -s container -s not-container (or YAML: scope: [container, not-container])
				// CLI parsing: parseScopeFilters() iterates through scopeFlags and calls
				// p.ContFilter.Parse() for EACH flag, accumulating values in the same filter.
				// First Parse("container") sets trueEnabled=true, then Parse("not-container")
				// sets falseEnabled=true. BoolFilter.Value() returns trueEnabled (true).
				// Empirical testing confirms: only containers match, so forContainer=true.
				p := createPolicyNoFilters(t, 0, "both-true-and-false", events.SecurityBPF)
				if err := p.ContFilter.Parse("container"); err != nil {
					t.Fatalf("failed to parse container filter: %v", err)
				}
				if err := p.ContFilter.Parse("not-container"); err != nil {
					t.Fatalf("failed to parse not-container filter: %v", err)
				}
				return []*Policy{p}
			},
			eventID:         events.SecurityBPF,
			expectHost:      false,
			expectContainer: true,
		},
		{
			name: "cross-policy OR logic: one host-only, one container-only",
			createPolicies: func(t *testing.T) []*Policy {
				return []*Policy{
					createPolicyWithContFilter(t, 0, "host-policy", events.SecurityBPF, "=false"),
					createPolicyWithContFilter(t, 1, "container-policy", events.SecurityBPF, "=true"),
				}
			},
			eventID:         events.SecurityBPF,
			expectHost:      true,
			expectContainer: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policies := tt.createPolicies(t)

			depsManager := dependencies.NewDependenciesManager(
				func(id events.ID) events.DependencyStrategy {
					return events.Core.GetDefinitionByID(id).GetDependencies()
				})

			policyManager, err := NewManager(ManagerConfig{}, depsManager, policies...)
			assert.NoError(t, err)

			forHost, forContainer := policyManager.IsContainerFilterSetOnEvent(tt.eventID)

			assert.Equal(t, tt.expectHost, forHost,
				"forHost mismatch: expected %v, got %v", tt.expectHost, forHost)
			assert.Equal(t, tt.expectContainer, forContainer,
				"forContainer mismatch: expected %v, got %v", tt.expectContainer, forContainer)
		})
	}
}
