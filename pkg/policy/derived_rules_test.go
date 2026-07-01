package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/pkg/events"
)

// buildEventRules builds an EventRules holding the given rules, populating the fields
// GetDerivedEventMatchedRules reads (rulesCount, ruleIDToEventRule, hasOverflow).
func buildEventRules(rules ...*EventRule) EventRules {
	er := EventRules{
		Rules:             rules,
		ruleIDToEventRule: make(map[uint]*EventRule, len(rules)),
	}
	var maxID uint
	for _, r := range rules {
		er.ruleIDToEventRule[r.ID] = r
		if r.ID >= maxID {
			maxID = r.ID
		}
	}
	er.rulesCount = maxID + 1
	er.hasOverflow = er.rulesCount > 64
	return er
}

// Test_GetDerivedEventMatchedRules_MultiLevelChain is a regression test for derived events
// being dropped in multi-level derivation/detector chains.
//
// When a policy selects a top consumer (e.g. a detector output) that depends on an
// intermediate derived event which in turn derives from a base event, every transitive
// dependency rule carries the TOP consumer's shared RuleData (so Data.EventID == top, not the
// intermediate). The previous implementation keyed on baseRule.Data.EventID == derivedEventID
// and therefore produced an EMPTY bitmap for the intermediate derive step (base -> intermediate),
// dropping the event before it could reach its consumer. This surfaced as kernel e2e failures
// such as PROCESS_EXECUTE_FAILED (execute_finished -> process_execute_failed -> detector). The
// fix maps by the shared RuleData pointer, so the chain bit propagates at every level.
func Test_GetDerivedEventMatchedRules_MultiLevelChain(t *testing.T) {
	const (
		evtTop  = events.ID(60000) // user/detector-selected consumer
		evtMid  = events.ID(60001) // intermediate derived event
		evtBase = events.ID(60002) // base event
	)

	// All rules in one chain share the top consumer's RuleData pointer, exactly as
	// addTransitiveDependencyRules builds them (deepCopyEventRules preserves the pointer).
	chainData := &RuleData{EventID: evtTop}

	pm := &PolicyManager{
		rules: map[events.ID]EventRules{
			evtTop: buildEventRules(&EventRule{
				ID: 0, Data: chainData, SelectionType: SelectedByUser,
			}),
			evtMid: buildEventRules(&EventRule{
				ID: 0, Data: chainData, SelectionType: SelectedByDependency, DerivedRuleID: 0,
			}),
			evtBase: buildEventRules(&EventRule{
				ID: 0, Data: chainData, SelectionType: SelectedByDependency, DerivedRuleID: 0,
			}),
		},
	}

	// base matched (rule 0) -> intermediate derived event: the previously-broken step.
	midMatched := pm.GetDerivedEventMatchedRules(evtMid, evtBase, []uint64{0b1})
	require.True(t, bitwise.HasBitInArray(midMatched, 0),
		"intermediate derived event must inherit the chain's matched bit (regression: was empty -> dropped)")

	// intermediate matched -> top consumer: the final step.
	topMatched := pm.GetDerivedEventMatchedRules(evtTop, evtMid, []uint64{0b1})
	require.True(t, bitwise.HasBitInArray(topMatched, 0),
		"final consumer must inherit the chain's matched bit")

	// A base rule from a DIFFERENT chain (distinct RuleData) must NOT propagate.
	otherData := &RuleData{EventID: evtTop}
	pm.rules[evtBase] = buildEventRules(&EventRule{
		ID: 0, Data: otherData, SelectionType: SelectedByDependency, DerivedRuleID: 0,
	})
	noMatch := pm.GetDerivedEventMatchedRules(evtMid, evtBase, []uint64{0b1})
	require.False(t, bitwise.HasBitInArray(noMatch, 0),
		"a base rule from a different chain must not propagate to the derived event")
}

// Test_GetDerivedEventMatchedRules_SingleLevel verifies the common single-level case (a policy
// directly selecting a derived event) still maps base -> derived correctly after the fix.
func Test_GetDerivedEventMatchedRules_SingleLevel(t *testing.T) {
	const (
		evtDerived = events.ID(60010) // user-selected derived event
		evtBase    = events.ID(60011) // its base
	)
	data := &RuleData{EventID: evtDerived}

	pm := &PolicyManager{
		rules: map[events.ID]EventRules{
			evtDerived: buildEventRules(&EventRule{
				ID: 0, Data: data, SelectionType: SelectedByUser,
			}),
			evtBase: buildEventRules(&EventRule{
				ID: 0, Data: data, SelectionType: SelectedByDependency, DerivedRuleID: 0,
			}),
		},
	}

	matched := pm.GetDerivedEventMatchedRules(evtDerived, evtBase, []uint64{0b1})
	require.True(t, bitwise.HasBitInArray(matched, 0),
		"single-level derivation must map the base's matched bit to the derived event")
}

// Test_DeriveGate_DependencyEventIsSelected guards the derive-table enablement predicate.
// A derived event pulled in only as a dependency (e.g. process_execute_failed consumed by a
// detector, or net_packet_dns feeding a datastore) MUST still be derived - so the derive gate
// has to use IsEventSelected ("has any rule", matching main's IsEventToSubmit), NOT
// ShouldEmitEvent (user-selected only). Using ShouldEmitEvent disabled dependency-only
// derivations, so the events were never produced (kernel e2e: PROCESS_EXECUTE_FAILED etc.).
func Test_DeriveGate_DependencyEventIsSelected(t *testing.T) {
	const evt = events.ID(60020)
	pm := &PolicyManager{
		rules: map[events.ID]EventRules{
			evt: buildEventRules(&EventRule{
				ID: 0, Data: &RuleData{EventID: evt}, SelectionType: SelectedByDependency,
			}),
		},
	}

	require.True(t, pm.IsEventSelected(evt),
		"a dependency-selected event must count as selected so its derivation runs")
	require.False(t, pm.ShouldEmitEvent(evt),
		"a dependency-only event is not user-emitted (ShouldEmitEvent is user-selected only) "+
			"- this is why the derive gate must use IsEventSelected, not ShouldEmitEvent")
}

// Test_GetAllRulesBitmap covers the seed used to recover a detector output whose base bitmap
// did not carry the chain bit (direct-input detectors): every rule bit set, nothing beyond.
func Test_GetAllRulesBitmap(t *testing.T) {
	const evt = events.ID(60030)
	pm := &PolicyManager{
		rules: map[events.ID]EventRules{
			evt: buildEventRules(
				&EventRule{ID: 0, Data: &RuleData{EventID: evt}, SelectionType: SelectedByUser},
				&EventRule{ID: 1, Data: &RuleData{EventID: evt}, SelectionType: SelectedByDependency},
				&EventRule{ID: 2, Data: &RuleData{EventID: evt}, SelectionType: SelectedByDependency},
			),
		},
	}

	bm := pm.GetAllRulesBitmap(evt)
	for i := uint(0); i < 3; i++ {
		require.True(t, bitwise.HasBitInArray(bm, i), "rule bit %d must be set", i)
	}
	require.False(t, bitwise.HasBitInArray(bm, 3), "no bit beyond rulesCount may be set")

	// Unknown event (no rules) yields an empty bitmap so matchPoliciesProto drops it.
	require.True(t, bitwise.IsBitmapArrayEmpty(pm.GetAllRulesBitmap(events.ID(99999))))
}
