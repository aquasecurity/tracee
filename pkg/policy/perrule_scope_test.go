package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// Test_PerRuleScopePushedToKernel verifies that a per-rule scope filter (a scope key inside a rule's
// `filters:` list, carried in rule.Data.ScopeFilter) is pushed to the kernel scope maps - not just
// applied in user space. This exercises the per-rule scope kernel pushdown in processRuleScopeFilters.
func Test_PerRuleScopePushedToKernel(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// A policy with NO policy-level scope, but a per-rule comm filter on openat.
	p := NewPolicy()
	p.Name = "perrule"
	sf := filters.NewScopeFilter()
	require.NoError(t, sf.Parse("comm", "=nginx"))
	p.Rules = map[events.ID]RuleData{
		events.Openat: {
			EventID:     events.Openat,
			ScopeFilter: sf,
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	maps, err := pm.computeFilterMaps(nil)
	require.NoError(t, err)

	found := false
	for _, byComm := range maps.commFilters {
		if _, ok := byComm["nginx"]; ok {
			found = true
		}
	}
	require.True(t, found, "per-rule comm scope value must be pushed to the kernel comm filter map")

	// The map value alone is not enough: the kernel skips a dimension whose "enabled" bit is unset, so the
	// scope config must also mark comm enabled for this rule (this is what the config path was missing).
	cfg := pm.computeScopeFiltersConfig(events.Openat)
	ruleID := pm.rules[events.Openat].Rules[0].ID
	require.True(t, bitwise.HasBitInArray(cfg.CommFilterEnabled, ruleID),
		"comm must be marked enabled in the scope config for the per-rule rule")
}

// Test_PerRuleNumericScopePushedToKernel is the numeric-dimension analogue of the comm test: a per-rule
// uid scope must land in the kernel uid map AND be marked enabled in the config. Guards the copy-paste
// across the numeric dims (uid/pid/mntns/pidns) added alongside comm.
func Test_PerRuleNumericScopePushedToKernel(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	p := NewPolicy()
	p.Name = "perrule-uid"
	sf := filters.NewScopeFilter()
	require.NoError(t, sf.Parse("uid", "=1000"))
	p.Rules = map[events.ID]RuleData{
		events.Openat: {
			EventID:     events.Openat,
			ScopeFilter: sf,
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	maps, err := pm.computeFilterMaps(nil)
	require.NoError(t, err)

	found := false
	for _, byUID := range maps.uidFilters {
		if _, ok := byUID[1000]; ok {
			found = true
		}
	}
	require.True(t, found, "per-rule uid scope value must be pushed to the kernel uid filter map")

	cfg := pm.computeScopeFiltersConfig(events.Openat)
	ruleID := pm.rules[events.Openat].Rules[0].ID
	require.True(t, bitwise.HasBitInArray(cfg.UIDFilterEnabled, ruleID),
		"uid must be marked enabled in the scope config for the per-rule rule")
	// An equal per-rule uid filter must NOT set match-if-key-missing: an empty policy filter reports
	// MatchIfKeyMissing()==true vacuously, and inheriting it would make the complement match (a leak).
	require.False(t, bitwise.HasBitInArray(cfg.UIDFilterMatchIfKeyMissing, ruleID),
		"an equal per-rule uid filter must NOT set match-if-key-missing")
}

// Test_PerRuleContainerScopePushedToKernel verifies that a per-rule container scope (a bool, config-only
// dimension with no value map) is marked enabled in the kernel scope config for its rule.
func Test_PerRuleContainerScopePushedToKernel(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	p := NewPolicy()
	p.Name = "perrule-container"
	sf := filters.NewScopeFilter()
	require.NoError(t, sf.Parse("container", "")) // is-container = true
	p.Rules = map[events.ID]RuleData{
		events.Openat: {
			EventID:     events.Openat,
			ScopeFilter: sf,
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	cfg := pm.computeScopeFiltersConfig(events.Openat)
	ruleID := pm.rules[events.Openat].Rules[0].ID
	require.True(t, bitwise.HasBitInArray(cfg.ContFilterEnabled, ruleID),
		"container must be marked enabled in the scope config for the per-rule rule")
}

// Test_PerRuleBinaryScopePushedToKernel verifies that a per-rule executable/binary scope lands in the
// kernel binary filter map AND is marked enabled in the config. Binary is kernel-enforced only.
func Test_PerRuleBinaryScopePushedToKernel(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	p := NewPolicy()
	p.Name = "perrule-bin"
	sf := filters.NewScopeFilter()
	require.NoError(t, sf.Parse("executable", "=/usr/bin/nc")) // bare path -> MntNS 0 (any namespace)
	p.Rules = map[events.ID]RuleData{
		events.Openat: {
			EventID:     events.Openat,
			ScopeFilter: sf,
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	maps, err := pm.computeFilterMaps(nil)
	require.NoError(t, err)

	found := false
	want := filters.NSBinary{MntNS: 0, Path: "/usr/bin/nc"}
	for _, byBin := range maps.binaryFilters {
		if _, ok := byBin[want]; ok {
			found = true
		}
	}
	require.True(t, found, "per-rule executable scope value must be pushed to the kernel binary filter map")

	cfg := pm.computeScopeFiltersConfig(events.Openat)
	ruleID := pm.rules[events.Openat].Rules[0].ID
	require.True(t, bitwise.HasBitInArray(cfg.BinPathFilterEnabled, ruleID),
		"executable must be marked enabled in the scope config for the per-rule rule")
	// An equal per-rule executable filter must NOT set match-if-key-missing (else the wrong-binary
	// complement matches - this is the bug the overflow-binary test caught).
	require.False(t, bitwise.HasBitInArray(cfg.BinPathFilterMatchIfKeyMissing, ruleID),
		"an equal per-rule executable filter must NOT set match-if-key-missing")
}

// Test_PerRuleUTSScopePushedToKernel verifies a per-rule uts (hostName) scope lands in the kernel uts map
// AND is marked enabled in the config, and that an equal filter does not set match-if-key-missing.
func Test_PerRuleUTSScopePushedToKernel(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	p := NewPolicy()
	p.Name = "perrule-uts"
	sf := filters.NewScopeFilter()
	require.NoError(t, sf.Parse("hostName", "=web01"))
	p.Rules = map[events.ID]RuleData{
		events.Openat: {
			EventID:     events.Openat,
			ScopeFilter: sf,
			DataFilter:  filters.NewDataFilter(),
			RetFilter:   filters.NewIntFilter(),
		},
	}

	pm, err := NewManager(ManagerConfig{}, depsManager, p)
	require.NoError(t, err)

	maps, err := pm.computeFilterMaps(nil)
	require.NoError(t, err)

	found := false
	for _, byUTS := range maps.utsFilters {
		if _, ok := byUTS["web01"]; ok {
			found = true
		}
	}
	require.True(t, found, "per-rule uts scope value must be pushed to the kernel uts filter map")

	cfg := pm.computeScopeFiltersConfig(events.Openat)
	ruleID := pm.rules[events.Openat].Rules[0].ID
	require.True(t, bitwise.HasBitInArray(cfg.UtsNsFilterEnabled, ruleID),
		"uts must be marked enabled in the scope config for the per-rule rule")
	require.False(t, bitwise.HasBitInArray(cfg.UtsNsFilterMatchIfKeyMissing, ruleID),
		"an equal per-rule uts filter must NOT set match-if-key-missing")
}

// Test_CombinedBinaryScopePolicyAndPerRule covers the fold of MULTIPLE enabled binary scope
// sources (policy scope + per-rule scope) into one kernel filter. Binary has no userland
// backstop, so before the fold a per-rule executable= was silently enforced NOWHERE whenever
// the policy scope also set one (first-enabled-source-wins dropped it).
func Test_CombinedBinaryScopePolicyAndPerRule(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	newPM := func(policyPath, perRulePath string) *PolicyManager {
		p := NewPolicy()
		p.Name = "combined-bin"
		require.NoError(t, p.BinaryFilter.Parse("="+policyPath))
		sf := filters.NewScopeFilter()
		require.NoError(t, sf.Parse("executable", "="+perRulePath))
		p.Rules = map[events.ID]RuleData{
			events.Openat: {
				EventID:     events.Openat,
				ScopeFilter: sf,
				DataFilter:  filters.NewDataFilter(),
				RetFilter:   filters.NewIntFilter(),
			},
		}
		pm, err := NewManager(ManagerConfig{}, depsManager, p)
		require.NoError(t, err)
		return pm
	}

	// lookup reports the rule's verdict for a path in the computed binary maps: equal
	// (equals bit set), or key-used non-match (key present, equals unset).
	lookup := func(pm *PolicyManager, path string) (inEqual, inNotEqual bool) {
		maps, err := pm.computeFilterMaps(nil)
		require.NoError(t, err)
		key := filters.NSBinary{MntNS: 0, Path: path}
		ruleID := pm.rules[events.Openat].Rules[0].ID
		word, bit := int(ruleID/64), ruleID%64
		for _, byBin := range maps.binaryFilters {
			bms, ok := byBin[key]
			if !ok || word >= len(bms) {
				continue
			}
			if bitwise.HasBit(bms[word].equalsInRules, bit) {
				inEqual = true
			} else if bitwise.HasBit(bms[word].keyUsedInRules, bit) {
				inNotEqual = true
			}
		}
		return inEqual, inNotEqual
	}

	// Same path in both sources: the AND keeps it (rule matches /a).
	pmSame := newPM("/usr/bin/a", "/usr/bin/a")
	eq, _ := lookup(pmSame, "/usr/bin/a")
	require.True(t, eq, "path present in BOTH sources must stay an equal match")

	// Different paths: the AND of executable=/a and executable=/b matches NOTHING - both keys
	// must resolve to a non-match (key present with equals unset), never to a silent
	// policy-only filter that would match /a.
	pmDiff := newPM("/usr/bin/a", "/usr/bin/b")
	eqA, neA := lookup(pmDiff, "/usr/bin/a")
	require.False(t, eqA, "policy path must NOT match: the per-rule executable rejects it")
	require.True(t, neA, "policy path must be a key-used non-match")
	eqB, neB := lookup(pmDiff, "/usr/bin/b")
	require.False(t, eqB, "per-rule path must NOT match: the policy scope rejects it")
	require.True(t, neB, "per-rule path must be a key-used non-match")

	// Both sources are equal-only filters, so the combined default must stay no-match.
	cfg := pmDiff.computeScopeFiltersConfig(events.Openat)
	ruleID := pmDiff.rules[events.Openat].Rules[0].ID
	require.True(t, bitwise.HasBitInArray(cfg.BinPathFilterEnabled, ruleID))
	require.False(t, bitwise.HasBitInArray(cfg.BinPathFilterMatchIfKeyMissing, ruleID),
		"combined equal-only binary filters must not set match-if-key-missing")
}
