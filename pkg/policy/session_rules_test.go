package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
)

// testEvent is a plain (non-bootstrap) event so added rules get predictable, low rule IDs.
const testEvent = events.SecurityFileOpen

func newTestManager(t *testing.T) *PolicyManager {
	t.Helper()
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := NewManager(ManagerConfig{}, depsManager)
	require.NoError(t, err)
	return pm
}

func treePolicy(t *testing.T, name, treeExpr string, evts ...events.ID) *Policy {
	t.Helper()
	p := NewPolicy()
	p.Name = name
	require.NoError(t, p.ProcessTreeFilter.Parse(treeExpr))
	for _, e := range evts {
		p.Rules[e] = RuleData{EventID: e}
	}
	return p
}

func followPolicy(name string, evts ...events.ID) *Policy {
	p := NewPolicy()
	p.Name = name
	p.Follow = true
	for _, e := range evts {
		p.Rules[e] = RuleData{EventID: e}
	}
	return p
}

// ruleIDForPolicy returns the rule ID assigned to policyName on eventID.
func ruleIDForPolicy(t *testing.T, pm *PolicyManager, eventID events.ID, policyName string) uint {
	t.Helper()
	for _, r := range pm.GetRules(eventID) {
		if r.Policy != nil && r.Policy.Name == policyName {
			return r.ID
		}
	}
	t.Fatalf("no rule for policy %q on event %d", policyName, eventID)
	return 0
}

// --- tree groups: a GROUP is a policy (not a root pid), so roots are unlimited ---

func TestComputeTreeGroups_PerPolicySortedStable(t *testing.T) {
	pm := newTestManager(t)
	// One policy with MANY roots — they must all fold into a single group (unlimited roots).
	require.NoError(t, pm.AddPolicy(treePolicy(t, "btree", "=1,2,3,4,5", testEvent)))
	require.NoError(t, pm.AddPolicy(treePolicy(t, "atree", "!=9", testEvent)))

	groups, err := pm.computeTreeGroups()
	require.NoError(t, err)
	// keyed by policy name, assigned in sorted order
	assert.Equal(t, map[string]uint8{"atree": 0, "btree": 1}, groups)
}

func TestComputeTreeGroups_CapIsLoudError(t *testing.T) {
	pm := newTestManager(t)
	for i := 0; i < 65; i++ { // > 64 policies using tree
		require.NoError(t, pm.AddPolicy(treePolicy(t, fmt.Sprintf("tree%03d", i), "=10", testEvent)))
	}
	_, err := pm.computeTreeGroups()
	require.Error(t, err, "more than 64 tree policies must be a hard error, not a silent drop")
}

func TestComputeTreeRuleTable(t *testing.T) {
	pm := newTestManager(t)
	require.NoError(t, pm.AddPolicy(treePolicy(t, "tree1", "=100", testEvent)))

	groups, err := pm.computeTreeGroups()
	require.NoError(t, err)
	table, err := pm.computeTreeRuleTable(testEvent, groups)
	require.NoError(t, err)

	require.Equal(t, uint32(1), table.NumGroups)
	g := table.Groups[0]
	assert.Equal(t, groups["tree1"], g.Group)

	ruleID := ruleIDForPolicy(t, pm, testEvent, "tree1")
	assert.NotZero(t, g.Rules&(uint64(1)<<ruleID), "tree1's rule bit must be set in its group")
}

func TestComputeTreeRuleTable_PerEventCapIsLoudError(t *testing.T) {
	pm := newTestManager(t)
	// 9 distinct tree policies all selecting the same event => 9 groups on that event > 8.
	for i := 0; i < 9; i++ {
		require.NoError(t, pm.AddPolicy(treePolicy(t, fmt.Sprintf("tree%d", i), "=10", testEvent)))
	}
	groups, err := pm.computeTreeGroups()
	require.NoError(t, err)
	_, err = pm.computeTreeRuleTable(testEvent, groups)
	require.Error(t, err, "more than maxTreeGroupsPerEvent groups on one event must be a hard error")
}

// --- follow groups: a GROUP is a follow-policy ---

func TestComputeFollowGroupsAndTable(t *testing.T) {
	pm := newTestManager(t)
	require.NoError(t, pm.AddPolicy(followPolicy("f1", testEvent)))

	groups, err := pm.computeFollowGroups()
	require.NoError(t, err)
	assert.Equal(t, map[string]uint8{"f1": 0}, groups)

	table, err := pm.computeFollowRuleTable(testEvent, groups)
	require.NoError(t, err)
	require.Equal(t, uint32(1), table.NumGroups)
	ruleID := ruleIDForPolicy(t, pm, testEvent, "f1")
	assert.NotZero(t, table.Groups[0].Rules&(uint64(1)<<ruleID))
}

func TestComputeFollowGroups_CapIsLoudError(t *testing.T) {
	pm := newTestManager(t)
	for i := 0; i < 65; i++ {
		require.NoError(t, pm.AddPolicy(followPolicy(fmt.Sprintf("f%03d", i), testEvent)))
	}
	_, err := pm.computeFollowGroups()
	require.Error(t, err)
}

// --- runtime EnableRule / DisableRule ---

func TestEnableDisableRule(t *testing.T) {
	pm := newTestManager(t)
	p := NewPolicy()
	p.Name = "p1"
	p.Rules[testEvent] = RuleData{EventID: testEvent}
	require.NoError(t, pm.AddPolicy(p))

	ruleID := ruleIDForPolicy(t, pm, testEvent, "p1")

	// initially nothing disabled
	assert.False(t, pm.AnyRulesDisabled())
	assert.False(t, bitwise.HasBitInArray(pm.GetDisabledRules(testEvent), ruleID))

	// disable -> bit set + gate open
	require.NoError(t, pm.DisableRule("p1", testEvent))
	assert.True(t, pm.AnyRulesDisabled())
	assert.True(t, bitwise.HasBitInArray(pm.GetDisabledRules(testEvent), ruleID))

	// enable -> bit cleared
	require.NoError(t, pm.EnableRule("p1", testEvent))
	assert.False(t, bitwise.HasBitInArray(pm.GetDisabledRules(testEvent), ruleID))
}

func TestDisableRule_Errors(t *testing.T) {
	pm := newTestManager(t)
	p := NewPolicy()
	p.Name = "p1"
	p.Rules[testEvent] = RuleData{EventID: testEvent}
	require.NoError(t, pm.AddPolicy(p))

	// unknown policy on an event that has rules
	require.Error(t, pm.DisableRule("ghost", testEvent))
	// event with no rules at all
	require.Error(t, pm.DisableRule("p1", events.Ptrace))
}

// copy-on-write: a snapshot taken before disabling must not observe the new disabled bit.
func TestDisableRule_CopyOnWrite(t *testing.T) {
	pm := newTestManager(t)
	p := NewPolicy()
	p.Name = "p1"
	p.Rules[testEvent] = RuleData{EventID: testEvent}
	require.NoError(t, pm.AddPolicy(p))
	ruleID := ruleIDForPolicy(t, pm, testEvent, "p1")

	before := pm.GetDisabledRules(testEvent) // snapshot (nil/empty)
	require.NoError(t, pm.DisableRule("p1", testEvent))
	after := pm.GetDisabledRules(testEvent)

	assert.False(t, bitwise.HasBitInArray(before, ruleID), "old snapshot must be unchanged")
	assert.True(t, bitwise.HasBitInArray(after, ruleID), "new snapshot must reflect the disable")
}
