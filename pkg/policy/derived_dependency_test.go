package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// Test_DerivedEventPullsInBaseAsDependency guards the invariant the decode-stage drop relies on (after the
// coarse hasDerivation keep was removed, see pkg/ebpf/events_pipeline.go): selecting a DERIVED event pulls
// its derive-from base into the rule set as a DEPENDENCY rule, so matchPolicies keeps the base (scope-aware)
// - not a coarse "can this type derive?" check. If a derived event stopped declaring its base dependency,
// this fails, catching the footgun before the base gets silently dropped at decode.
func Test_DerivedEventPullsInBaseAsDependency(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// A policy selecting the DERIVED event container_create (which derives from cgroup_mkdir).
	p := NewPolicy()
	p.Name = "derived"
	p.Rules = map[events.ID]RuleData{
		events.ContainerCreate: {
			EventID:     events.ContainerCreate,
			ScopeFilter: filters.NewScopeFilter(),
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	// The derive-from base (cgroup_mkdir) must be present in the rule set...
	baseRules, ok := pm.rules[events.CgroupMkdir]
	require.True(t, ok, "the derive-from base (cgroup_mkdir) must be pulled in when the derived event is selected")

	// ...and it must carry a DEPENDENCY rule - that is what keeps the base at decode via matchPolicies.
	hasDep := false
	for _, r := range baseRules.Rules {
		if r.IsDependency() {
			hasDep = true
		}
	}
	require.True(t, hasDep, "the base must carry a dependency rule (else the decode drop would discard it)")
}

// Test_RemovePolicy_KeepsDependencyNeededBase guards the runtime-removal semantics: P1 selects a
// BASE event directly while P2 selects a DERIVED event whose chain depends on that same base.
// Removing P1 must strip P1's rules everywhere but KEEP the base's rule table alive (P2's
// dependency rule resolves derived matches through it); a base deleted wholesale would silently
// kill P2's derived events until restart. Removing P2 afterwards must then drop the base's
// dependency rules (nothing needs them), leaving no leftovers of either policy.
func Test_RemovePolicy_KeepsDependencyNeededBase(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	newRuleData := func(id events.ID) RuleData {
		return RuleData{
			EventID:     id,
			ScopeFilter: filters.NewScopeFilter(),
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		}
	}

	// P1 selects the base (cgroup_mkdir) directly.
	p1 := NewPolicy()
	p1.Name = "p1-base"
	p1.Rules = map[events.ID]RuleData{events.CgroupMkdir: newRuleData(events.CgroupMkdir)}

	// P2 selects the derived event (container_create), which depends on cgroup_mkdir.
	p2 := NewPolicy()
	p2.Name = "p2-derived"
	p2.Rules = map[events.ID]RuleData{events.ContainerCreate: newRuleData(events.ContainerCreate)}

	pm, err := NewManager(ManagerConfig{}, depsManager, p1, p2)
	require.NoError(t, err)

	countRulesOf := func(eventID events.ID, policyName string) int {
		n := 0
		if er, ok := pm.rules[eventID]; ok {
			for _, r := range er.Rules {
				if r.Policy != nil && r.Policy.Name == policyName {
					n++
				}
			}
		}
		return n
	}

	require.Positive(t, countRulesOf(events.CgroupMkdir, "p1-base"), "guard: P1's user rule on the base")
	require.Positive(t, countRulesOf(events.CgroupMkdir, "p2-derived"), "guard: P2's dependency rule on the base")

	// Remove P1: the base must SURVIVE (P2's chain needs it) with P1's rules gone.
	require.NoError(t, pm.RemovePolicy("p1-base"))
	baseRules, ok := pm.rules[events.CgroupMkdir]
	require.True(t, ok, "base must survive P1's removal - P2's derived chain resolves through it")
	require.Zero(t, countRulesOf(events.CgroupMkdir, "p1-base"), "P1's rules must be gone from the base")
	require.Positive(t, countRulesOf(events.CgroupMkdir, "p2-derived"), "P2's dependency rule must survive")

	// The surviving dependency rule must still map derived matches (the chain is intact).
	snap := pm.LoadSnapshot()
	var depRuleID uint
	for _, r := range baseRules.Rules {
		if r.IsDependency() {
			depRuleID = r.ID
		}
	}
	baseBitmap := []uint64{1 << depRuleID}
	mapped := snap.GetDerivedEventMatchedRules(events.ContainerCreate, events.CgroupMkdir, baseBitmap)
	require.NotEmpty(t, mapped, "P2's derived mapping must survive P1's removal")

	// Remove P2: now nothing needs the base - its dependency rules must be pruned, not leak.
	require.NoError(t, pm.RemovePolicy("p2-derived"))
	require.Zero(t, countRulesOf(events.CgroupMkdir, "p2-derived"),
		"P2's dependency rules must be pruned when P2 is removed (no zombie chains)")
}

// Test_Readd_NoDependencyRuleDuplication guards the rebuild dedup: re-applying/updating a policy
// that selects a derived event must not duplicate its dependency rule on the base (the dedup is
// by logical chain key, not RuleData pointer identity - a fresh pointer is created per rebuild).
func Test_Readd_NoDependencyRuleDuplication(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	newPolicy := func() *Policy {
		p := NewPolicy()
		p.Name = "derived"
		p.Rules = map[events.ID]RuleData{
			events.ContainerCreate: {
				EventID:     events.ContainerCreate,
				ScopeFilter: filters.NewScopeFilter(),
				DataFilter:  filters.NewDataFilter(),
				RetFilter:   filters.NewIntFilter(),
			},
		}
		return p
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, newPolicy())
	require.NoError(t, err)

	countDeps := func() int {
		n := 0
		if er, ok := pm.rules[events.CgroupMkdir]; ok {
			for _, r := range er.Rules {
				if r.IsDependency() {
					n++
				}
			}
		}
		return n
	}
	before := countDeps()
	require.Positive(t, before, "guard: derived selection must create a dependency rule")

	// Churn the policy several times; the dependency rule count on the base must not grow.
	for i := 0; i < 5; i++ {
		require.NoError(t, pm.UpdatePolicy(newPolicy()))
	}
	require.Equal(t, before, countDeps(),
		"dependency rules duplicated across rebuilds (pointer-identity dedup regression)")
}
