package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// Test_updateRulesForEvent_KeepsDependencyRuleInUserland is a regression test for the rebuild path
// in updateRulesForEvent. When an event is rebuilt (because a policy selects it directly) while it
// already carries a scope-filtered dependency rule - as addTransitiveDependencyRules attaches when
// another event that depends on it is selected - that dependency rule must remain in UserlandRules
// so its scope is still re-checked in userland. The existingDepRules loop previously appended these
// only to Rules, dropping them from UserlandRules and silently skipping kernel-unrepresentable
// scope (hostname/podName/...) on the base event.
func Test_updateRulesForEvent_KeepsDependencyRuleInUserland(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	const evt = events.SecurityFileOpen

	// Register evt in the dependency graph so updateRulesForEvent's GetEvent(evt) succeeds.
	_, err = pm.evtsDepsManager.SelectEvent(evt)
	require.NoError(t, err)

	// A scope-filtered dependency rule already attached to evt (the "existingDepRules" case): its
	// Data belongs to some dependent/derived event, and it carries a scope filter.
	depScope := filters.NewScopeFilter()
	require.NoError(t, depScope.Parse("comm", "=bash"))
	depRule := &EventRule{
		ID:            0,
		Data:          &RuleData{EventID: events.ID(1 << 20), ScopeFilter: depScope},
		SelectionType: SelectedByDependency,
	}
	require.True(t, isRuleFilterableInUserland(depRule), "guard: dep rule must be userland-filterable")

	tempRules := map[events.ID]EventRules{
		evt: {
			Rules:             []*EventRule{depRule},
			UserlandRules:     []*EventRule{depRule},
			ruleIDToEventRule: map[uint]*EventRule{0: depRule},
			rulesCount:        1,
			enabled:           true,
		},
	}

	// A policy that directly selects evt triggers the rebuild (the existingDepRules path).
	pol := NewPolicy()
	pol.Name = "direct"
	pol.Rules[evt] = RuleData{EventID: evt, ScopeFilter: filters.NewScopeFilter()}
	tempPolicies := map[string]*Policy{pol.Name: pol}

	require.NoError(t, pm.updateRulesForEvent(evt, tempRules, tempPolicies))

	// Regression assertion: the dependency rule must still be in UserlandRules after the rebuild.
	depInUserland := false
	for _, r := range tempRules[evt].UserlandRules {
		if r.SelectionType == SelectedByDependency {
			depInUserland = true
			break
		}
	}
	require.True(t, depInUserland,
		"scope-filtered dependency rule was dropped from UserlandRules on rebuild (regression)")
}

// Test_updateRulesForEvent_OverflowBoundary guards the hasOverflow boundary: the kernel's single
// u64 matched_rules bitmap represents rule IDs 0-63, so exactly 64 rules (IDs 0-63) still fit and
// must NOT set hasOverflow; only a 65th rule (ID 64) does. Guards the >64 (not >=64) condition.
func Test_updateRulesForEvent_OverflowBoundary(t *testing.T) {
	t.Parallel()

	const evt = events.SecurityFileOpen
	for _, tc := range []struct {
		name         string
		total        int // total rules for evt = seeded dependency rules + 1 user rule
		wantOverflow bool
	}{
		{"64_rules_fit_one_u64", 64, false},
		{"65_rules_overflow", 65, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			depsManager := dependencies.NewDependenciesManager(
				func(id events.ID) events.DependencyStrategy {
					return events.Core.GetDefinitionByID(id).GetDependencies()
				})
			pm, err := NewManager(ManagerConfig{}, depsManager)
			require.NoError(t, err)
			_, err = pm.evtsDepsManager.SelectEvent(evt)
			require.NoError(t, err)

			// Seed (total-1) dependency rules; the policy below contributes the final user rule.
			nDeps := tc.total - 1
			depRules := make([]*EventRule, nDeps)
			ruleIDToEventRule := make(map[uint]*EventRule, nDeps)
			for i := 0; i < nDeps; i++ {
				r := &EventRule{
					ID:            uint(i),
					Data:          &RuleData{EventID: events.ID(1 << 20)},
					SelectionType: SelectedByDependency,
				}
				depRules[i] = r
				ruleIDToEventRule[uint(i)] = r
			}
			tempRules := map[events.ID]EventRules{
				evt: {
					Rules:             depRules,
					ruleIDToEventRule: ruleIDToEventRule,
					rulesCount:        uint(nDeps),
					enabled:           true,
				},
			}

			pol := NewPolicy()
			pol.Name = "u"
			pol.Rules[evt] = RuleData{EventID: evt}
			tempPolicies := map[string]*Policy{pol.Name: pol}

			require.NoError(t, pm.updateRulesForEvent(evt, tempRules, tempPolicies))
			require.Equal(t, uint(tc.total), tempRules[evt].rulesCount, "rulesCount")
			require.Equal(t, tc.wantOverflow, tempRules[evt].hasOverflow,
				"hasOverflow with %d total rules", tc.total)
		})
	}
}

// Test_updateRulesForEvent_DeterministicRuleIDs verifies that rule IDs (bitmap positions) are
// assigned in a stable, name-sorted policy order rather than Go's randomized map-iteration order,
// so IDs are reproducible across runs. Policies are added out of name order on purpose.
func Test_updateRulesForEvent_DeterministicRuleIDs(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	const evt = events.SecurityFileOpen
	for _, name := range []string{"policy_c", "policy_a", "policy_b"} {
		p := NewPolicy()
		p.Name = name
		p.Rules[evt] = RuleData{EventID: evt}
		require.NoError(t, pm.AddPolicy(p))
	}

	idA := ruleIDForPolicy(t, pm, evt, "policy_a")
	idB := ruleIDForPolicy(t, pm, evt, "policy_b")
	idC := ruleIDForPolicy(t, pm, evt, "policy_c")
	require.True(t, idA < idB && idB < idC,
		"rule IDs must follow name-sorted policy order (a<b<c); got a=%d b=%d c=%d", idA, idB, idC)
}
