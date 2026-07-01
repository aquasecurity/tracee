package ebpf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// ovfEvent is a non-bootstrap event, so added policy rules get IDs 0..N-1 with no interference.
const ovfEvent = events.SecurityFileOpen

// buildManagerSelecting returns a PolicyManager where n distinct policies each select ovfEvent
// with no scope filters (so every rule should match unconditionally).
func buildManagerSelecting(t *testing.T, n int) *policy.PolicyManager {
	t.Helper()
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := policy.NewManager(policy.ManagerConfig{}, depsManager)
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		p := policy.NewPolicy()
		p.Name = fmt.Sprintf("p%03d", i)
		p.Rules[ovfEvent] = policy.RuleData{EventID: ovfEvent}
		require.NoError(t, pm.AddPolicy(p))
	}
	return pm
}

// Regression test for the review fix: overflow rules (ID >= 64) that have NO scope filter must
// still match (the earlier version returned early when an event had no scope-filter config,
// silently dropping them). With 65 policies, rule ID 64 lives in overflow word 1 and must be set.
func TestMatchOverflowRules_UnconditionalRulesMatch(t *testing.T) {
	t.Parallel()

	pm := buildManagerSelecting(t, 65) // rules 0..64 on ovfEvent => hasOverflow
	tr := &Tracee{policyManager: pm}

	ev := &events.PipelineEvent{
		EventID:            ovfEvent,
		MatchedRulesBitmap: []uint64{0}, // word 0 (kernel-owned) value is irrelevant here
	}
	tr.matchOverflowRules(ev)

	require.GreaterOrEqual(t, len(ev.MatchedRulesBitmap), 2, "overflow word must be allocated")
	// rule 64 = bit 0 of word 1; no scope filter => candidate => set.
	assert.Equal(t, uint64(0b1), ev.MatchedRulesBitmap[1],
		"the 65th rule (ID 64) has no scope filter and must match unconditionally")
}

// Non-overflow events (<=64 rules) must be left untouched by the overflow matcher.
func TestMatchOverflowRules_NoOverflowNoop(t *testing.T) {
	t.Parallel()

	pm := buildManagerSelecting(t, 3) // well under 64
	tr := &Tracee{policyManager: pm}

	ev := &events.PipelineEvent{
		EventID:            ovfEvent,
		MatchedRulesBitmap: []uint64{0b101},
	}
	tr.matchOverflowRules(ev)

	assert.Equal(t, []uint64{0b101}, ev.MatchedRulesBitmap, "non-overflow event bitmap must be unchanged")
}

// clearDisabledRules: gate is closed until something is disabled (no-op), then it clears the
// disabled rule's bit. Exercises Tracee + PolicyManager together.
func TestClearDisabledRules_Integration(t *testing.T) {
	t.Parallel()

	pm := buildManagerSelecting(t, 1)
	tr := &Tracee{policyManager: pm}

	var ruleID uint
	for _, r := range pm.GetRules(ovfEvent) {
		if r.Policy != nil && r.Policy.Name == "p000" {
			ruleID = r.ID
		}
	}
	bit := uint64(1) << ruleID

	// Gate closed (nothing disabled yet) => clearDisabledRules is a no-op.
	bitmap := []uint64{bit}
	tr.clearDisabledRules(ovfEvent, bitmap)
	assert.Equal(t, bit, bitmap[0], "no rule disabled yet: bitmap must be unchanged")

	// Disable the rule => its bit is cleared.
	require.NoError(t, pm.DisableRule("p000", ovfEvent))
	bitmap = []uint64{bit}
	tr.clearDisabledRules(ovfEvent, bitmap)
	assert.Equal(t, uint64(0), bitmap[0], "disabled rule's bit must be cleared")

	// Re-enable => bit survives again.
	require.NoError(t, pm.EnableRule("p000", ovfEvent))
	bitmap = []uint64{bit}
	tr.clearDisabledRules(ovfEvent, bitmap)
	assert.Equal(t, bit, bitmap[0], "re-enabled rule's bit must survive")
}
