package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/bitwise"
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

// Test_updateRulesForEvent_DeterministicRuleIDs verifies that a fresh manager assigns rule IDs (bitmap
// positions) in name-sorted policy order regardless of the initial-policy slice order, so IDs are reproducible
// across runs. (Rule IDs are now assignment-order-stable - they no longer renumber on add/remove - so the
// fresh load is sorted to keep this property; runtime add/remove keeps existing IDs, see Test_StableRuleIDs.)
func Test_updateRulesForEvent_DeterministicRuleIDs(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	const evt = events.SecurityFileOpen
	// Provided out of name order on purpose; a fresh manager sorts the initial load.
	var initial []*Policy
	for _, name := range []string{"policy_c", "policy_a", "policy_b"} {
		p := NewPolicy()
		p.Name = name
		p.Rules[evt] = RuleData{EventID: evt}
		initial = append(initial, p)
	}
	pm, err := NewManager(ManagerConfig{}, depsManager, initial...)
	require.NoError(t, err)

	idA := ruleIDForPolicy(t, pm, evt, "policy_a")
	idB := ruleIDForPolicy(t, pm, evt, "policy_b")
	idC := ruleIDForPolicy(t, pm, evt, "policy_c")
	require.True(t, idA < idB && idB < idC,
		"a fresh load must produce name-sorted rule IDs (a<b<c); got a=%d b=%d c=%d", idA, idB, idC)
}

// Test_StableRuleIDs verifies the runtime-stability property that makes matched-rules attribution safe across
// concurrent policy changes: adding a policy at runtime does not renumber existing rules' IDs (even a
// lower-sorting one), and a removed policy's ID is reused by the next new rule.
func Test_StableRuleIDs(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	const evt = events.SecurityFileOpen
	addPol := func(name string) {
		p := NewPolicy()
		p.Name = name
		p.Rules[evt] = RuleData{EventID: evt}
		require.NoError(t, pm.AddPolicy(p))
	}

	addPol("base")
	baseID := ruleIDForPolicy(t, pm, evt, "base")

	// A lower-sorting policy added at runtime must NOT renumber base.
	addPol("aaa")
	require.Equal(t, baseID, ruleIDForPolicy(t, pm, evt, "base"),
		"base must keep its ID when a lower-sorting policy is added at runtime")
	aaaID := ruleIDForPolicy(t, pm, evt, "aaa")
	require.NotEqual(t, baseID, aaaID)

	// Removing a policy frees its ID; base stays stable; the freed ID is reused by the next new rule.
	require.NoError(t, pm.RemovePolicy("aaa"))
	require.Equal(t, baseID, ruleIDForPolicy(t, pm, evt, "base"), "base stable after a removal")
	addPol("zzz")
	require.Equal(t, aaaID, ruleIDForPolicy(t, pm, evt, "zzz"),
		"a removed policy's ID must be reused by the next new rule")
	require.Equal(t, baseID, ruleIDForPolicy(t, pm, evt, "base"), "base still stable after reuse")
}

// Test_isRuleFilterableInUserland_DetectorScope covers the Phase 2 rule-local scope filter: a
// dependency rule that carries a detector-declared scope filter must be userland-filterable (so
// matchPolicies re-checks it), even with no Data-level scope/data/ret filters.
func Test_isRuleFilterableInUserland_DetectorScope(t *testing.T) {
	t.Parallel()

	scope := filters.NewScopeFilter()
	require.NoError(t, scope.Parse("comm", "=bash"))
	depRule := &EventRule{
		Data:                &RuleData{EventID: events.SecurityFileOpen, ScopeFilter: filters.NewScopeFilter()},
		SelectionType:       SelectedByDependency,
		DetectorScopeFilter: scope,
	}
	require.True(t, isRuleFilterableInUserland(depRule),
		"dependency rule with a detector scope filter must be userland-filterable")

	depRule.DetectorScopeFilter = nil
	require.False(t, isRuleFilterableInUserland(depRule),
		"dependency rule with no filters must not be userland-filterable")
}

// Test_isRuleFilterableInUserland_DetectorData: a dependency rule carrying a detector data filter is
// userland-filterable, because that filter is on the base event's own schema (unlike Data.DataFilter).
func Test_isRuleFilterableInUserland_DetectorData(t *testing.T) {
	t.Parallel()

	df := filters.NewDetectorDataFilter()
	require.NoError(t, df.Parse(events.SchedProcessExec, "pathname", "=/usr/bin/nc"))
	depRule := &EventRule{
		Data:               &RuleData{EventID: events.SchedProcessExec},
		SelectionType:      SelectedByDependency,
		DetectorDataFilter: df,
	}
	require.True(t, isRuleFilterableInUserland(depRule),
		"dependency rule with a detector data filter must be userland-filterable")

	depRule.DetectorDataFilter = nil
	require.False(t, isRuleFilterableInUserland(depRule),
		"dependency rule with no filters must not be userland-filterable")
}

// Test_addTransitiveDependencyRules_DetectorScopePushdown covers the Phase 2 bridge: a detector
// scope filter declared for a (detector -> base) edge (via SetDetectorScopeFilters) is attached to
// the base event's dependency rule when a policy selects the detector event.
func Test_addTransitiveDependencyRules_DetectorScopePushdown(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	// Find a real event D that depends on another event B (direct dependency).
	var D, B events.ID
	found := false
	for _, def := range events.Core.GetDefinitions() {
		if deps := def.GetDependencies().GetPrimaryDependencies().GetIDs(); len(deps) > 0 {
			D, B = def.GetID(), deps[0]
			found = true
			break
		}
	}
	require.True(t, found, "need a real event with an event dependency for this test")

	// Declare a detector scope filter for the (D -> B) edge, then select D.
	scope := filters.NewScopeFilter()
	require.NoError(t, scope.Parse("comm", "=bash"))
	pm.SetDetectorScopeFilters(map[events.ID]map[events.ID]*filters.ScopeFilter{
		D: {B: scope},
	})

	p := NewPolicy()
	p.Name = "sel_detector"
	p.Rules[D] = RuleData{EventID: D}
	require.NoError(t, pm.AddPolicy(p))

	// B's dependency rule (from D's chain) must carry the declared detector scope filter.
	gotScope := false
	for _, r := range pm.GetRules(B) {
		if r.SelectionType == SelectedByDependency && r.DetectorScopeFilter == scope {
			gotScope = true
			break
		}
	}
	require.True(t, gotScope,
		"base event %d dependency rule must carry the detector scope filter for the %d->%d edge", B, D, B)
}

// Test_addTransitiveDependencyRules_DetectorDataPushdown is the data-filter analogue of the scope
// bridge test: a detector data filter declared for a (detector -> base) edge is attached to the base
// event's dependency rule when a policy selects the detector event.
func Test_addTransitiveDependencyRules_DetectorDataPushdown(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	const B = events.SchedProcessExec // has a "pathname" data field

	// Find a real event D that directly depends on B.
	var D events.ID
	found := false
	for _, def := range events.Core.GetDefinitions() {
		for _, dep := range def.GetDependencies().GetPrimaryDependencies().GetIDs() {
			if dep == B {
				D, found = def.GetID(), true
				break
			}
		}
		if found {
			break
		}
	}
	require.True(t, found, "need a real event depending on sched_process_exec")

	// Declare a detector data filter for the (D -> B) edge, then select D.
	df := filters.NewDetectorDataFilter()
	require.NoError(t, df.Parse(B, "pathname", "=/usr/bin/nc"))
	pm.SetDetectorDataFilters(map[events.ID]map[events.ID]*filters.DataFilter{
		D: {B: df},
	})

	p := NewPolicy()
	p.Name = "sel_detector"
	p.Rules[D] = RuleData{EventID: D}
	require.NoError(t, pm.AddPolicy(p))

	gotData := false
	for _, r := range pm.GetRules(B) {
		if r.SelectionType == SelectedByDependency && r.DetectorDataFilter == df {
			gotData = true
			break
		}
	}
	require.True(t, gotData,
		"base event %d dependency rule must carry the detector data filter for the %d->%d edge", B, D, B)
}

// Test_RecomputeRules_AppliesDetectorScopeAfterPolicyLoad mirrors the real init order: policies are
// loaded (rules built) BEFORE detectors register and their scope filters are known. SetDetectorScope
// Filters + RecomputeRules must then thread the detector scope onto the already-built base dep rules.
func Test_RecomputeRules_AppliesDetectorScopeAfterPolicyLoad(t *testing.T) {
	t.Parallel()

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)

	var D, B events.ID
	found := false
	for _, def := range events.Core.GetDefinitions() {
		if deps := def.GetDependencies().GetPrimaryDependencies().GetIDs(); len(deps) > 0 {
			D, B = def.GetID(), deps[0]
			found = true
			break
		}
	}
	require.True(t, found, "need a real event with an event dependency")

	// Policy loaded BEFORE the detector scope is known (as at NewManager, before registerAllDetectors).
	p := NewPolicy()
	p.Name = "sel_detector"
	p.Rules[D] = RuleData{EventID: D}
	require.NoError(t, pm.AddPolicy(p))

	for _, r := range pm.GetRules(B) {
		require.Nil(t, r.DetectorScopeFilter, "no detector scope before SetDetectorScopeFilters + RecomputeRules")
	}

	// Detectors register later: install the filters, then recompute.
	scope := filters.NewScopeFilter()
	require.NoError(t, scope.Parse("comm", "=bash"))
	pm.SetDetectorScopeFilters(map[events.ID]map[events.ID]*filters.ScopeFilter{D: {B: scope}})
	require.NoError(t, pm.RecomputeRules())

	gotScope := false
	for _, r := range pm.GetRules(B) {
		if r.SelectionType == SelectedByDependency && r.DetectorScopeFilter == scope {
			gotScope = true
			break
		}
	}
	require.True(t, gotScope, "base dep rule must carry the detector scope after RecomputeRules")
}

// Test_computeScopeFiltersConfig_DetectorScopePushdown covers increment 3: a rule's detector-declared
// scope dimensions (with no policy filter for them) must enable the matching kernel filters for that
// rule, so the base event is filtered in-kernel.
func Test_computeScopeFiltersConfig_DetectorScopePushdown(t *testing.T) {
	t.Parallel()

	const evt = events.SecurityFileOpen
	scope := filters.NewScopeFilter()
	require.NoError(t, scope.Parse("comm", "=bash"))
	require.NoError(t, scope.Parse("uid", "=0"))
	require.NoError(t, scope.Parse("hostPid", "=1"))
	require.NoError(t, scope.Parse("mntns", "=100"))
	require.NoError(t, scope.Parse("pidns", "=200"))

	rule := &EventRule{
		ID:                  0,
		Policy:              NewPolicy(), // no policy-level scope filters
		SelectionType:       SelectedByDependency,
		DetectorScopeFilter: scope,
	}
	pm := &PolicyManager{
		rules: map[events.ID]EventRules{
			evt: {Rules: []*EventRule{rule}, rulesCount: 1},
		},
	}

	// With the detector scope, each declared dimension must enable its kernel filter for the rule.
	cfg := pm.computeScopeFiltersConfig(evt)
	for name, enabled := range map[string][]uint64{
		"comm":  cfg.CommFilterEnabled,
		"uid":   cfg.UIDFilterEnabled,
		"pid":   cfg.PIDFilterEnabled,
		"mntns": cfg.MntNsFilterEnabled,
		"pidns": cfg.PidNsFilterEnabled,
	} {
		require.True(t, bitwise.HasBitInArray(enabled, 0),
			"detector %s scope must enable the %s filter for the rule in the kernel config", name, name)
	}

	// Without a detector scope (and no policy scope), none of them may be enabled.
	rule.DetectorScopeFilter = nil
	cfg = pm.computeScopeFiltersConfig(evt)
	for name, enabled := range map[string][]uint64{
		"comm":  cfg.CommFilterEnabled,
		"uid":   cfg.UIDFilterEnabled,
		"pid":   cfg.PIDFilterEnabled,
		"mntns": cfg.MntNsFilterEnabled,
		"pidns": cfg.PidNsFilterEnabled,
	} {
		require.False(t, bitwise.HasBitInArray(enabled, 0),
			"%s filter must not be enabled when neither policy nor detector sets it", name)
	}
}

// Test_processDataFilter_DetectorPathnamePushdown covers D3: a detector's pathname data filter seeds
// the base event's kernel exact-match config for the rule, and a nil filter is a no-op.
func Test_processDataFilter_DetectorPathnamePushdown(t *testing.T) {
	t.Parallel()

	const evt = events.SchedProcessExec
	pm := &PolicyManager{}
	fm := &filterMaps{
		dataFilterConfigs: make(map[events.ID]dataFilterConfig),
		dataExactFilters:  make(map[filterVersionKey]map[string][]ruleBitmap),
		dataPrefixFilters: make(map[filterVersionKey]map[string][]ruleBitmap),
		dataSuffixFilters: make(map[filterVersionKey]map[string][]ruleBitmap),
	}
	vKey := filterVersionKey{Version: 1, EventID: uint32(evt)}

	// A detector pathname data filter (exact) must seed the kernel exact-match config for the rule.
	df := filters.NewDetectorDataFilter()
	require.NoError(t, df.Parse(evt, "pathname", "=/usr/bin/nc"))
	require.NoError(t, pm.processDataFilter(fm, vKey, 0, df, evt))

	cfg, ok := fm.dataFilterConfigs[evt]
	require.True(t, ok, "detector pathname filter must create a data-filter config for the event")
	require.True(t, bitwise.HasBitInArray(cfg.string.exactEnabled, 0),
		"detector pathname exact filter must enable exact matching for the rule in the kernel config")

	// A nil detector data filter is a no-op (no panic, no config change).
	require.NoError(t, pm.processDataFilter(fm, vKey, 1, nil, evt))
}
