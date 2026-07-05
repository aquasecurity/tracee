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
}
