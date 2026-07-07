package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

// Test_Snapshot_RetentionAndIsolation verifies the runtime-swap correctness property: a Snapshot captured by a
// reader (as the pipeline does per event at decode via LoadSnapshot) keeps returning the version it was loaded
// under, even after a concurrent mutation publishes a new snapshot. This is what lets an in-flight event resolve
// its matched-rules bitmap consistently across a policy change - the same bitmap position must not be
// reinterpreted against a newer rule set at a later stage.
func Test_Snapshot_RetentionAndIsolation(t *testing.T) {
	const evt = events.ID(60100)

	pm := &PolicyManager{
		rules: map[events.ID]EventRules{
			evt: buildEventRules(&EventRule{
				ID: 0, Policy: &Policy{Name: "p-old"}, SelectionType: SelectedByUser,
			}),
		},
	}
	pm.publishSnapshot()

	// A reader captures the snapshot once (as decode does).
	s1 := pm.LoadSnapshot()
	require.Equal(t, []string{"p-old"}, s1.GetMatchedRulesInfo(evt, []uint64{0b1}), "captured snapshot sees p-old")
	require.Equal(t, uint(1), s1.GetRulesCount(evt))
	require.True(t, s1.IsEventSelected(evt))

	// Mutation: bit 0 now belongs to a different policy; publish a new snapshot.
	pm.rules[evt] = buildEventRules(&EventRule{
		ID: 0, Policy: &Policy{Name: "p-new"}, SelectionType: SelectedByUser,
	})
	pm.publishSnapshot()
	s2 := pm.LoadSnapshot()

	// Retention: the previously captured handle is UNCHANGED - bit 0 still attributes to p-old.
	require.Equal(t, []string{"p-old"}, s1.GetMatchedRulesInfo(evt, []uint64{0b1}),
		"retention: the captured snapshot must still resolve bit 0 to p-old after the swap")
	// The latest snapshot sees the new attribution.
	require.Equal(t, []string{"p-new"}, s2.GetMatchedRulesInfo(evt, []uint64{0b1}),
		"the latest snapshot resolves bit 0 to p-new")

	// Mutation: remove the event entirely; publish.
	delete(pm.rules, evt)
	pm.publishSnapshot()
	s3 := pm.LoadSnapshot()

	// Retention across removal: the old handle still has the event; the latest does not.
	require.Equal(t, []string{"p-old"}, s1.GetMatchedRulesInfo(evt, []uint64{0b1}),
		"retention: the captured snapshot must still see the removed event")
	require.True(t, s1.IsEventSelected(evt))
	require.False(t, s3.IsEventSelected(evt), "latest snapshot no longer has the removed event")
	require.Empty(t, s3.GetMatchedRulesInfo(evt, []uint64{0b1}))
}

// Test_Snapshot_NilSafe verifies every Snapshot read method returns the empty default on a nil receiver (the
// pipeline's fallback path and the PolicyManager wrappers rely on this before the first publish).
func Test_Snapshot_NilSafe(t *testing.T) {
	const evt = events.ID(60101)
	var s *Snapshot

	require.Nil(t, s.GetRules(evt))
	require.Nil(t, s.GetUserlandRules(evt))
	require.Nil(t, s.GetFilterMaps())
	require.Nil(t, s.GetDisabledRules(evt))
	require.Nil(t, s.GetSelectedEvents())
	require.False(t, s.IsEventSelected(evt))
	require.False(t, s.IsEventEnabled(evt))
	require.False(t, s.HasOverflowRules(evt))
	require.False(t, s.ShouldEmitEvent(evt))
	require.Zero(t, s.GetRulesCount(evt))
	require.Empty(t, s.GetMatchedRulesInfo(evt, []uint64{0b1}))
	require.Empty(t, s.GetDerivedEventMatchedRules(evt, evt, []uint64{0b1}))
	require.Equal(t, []uint64{0}, s.GetContainerFilteredRulesBitmap(evt)) // documented empty default
	require.Empty(t, s.GetAllMatchedRulesBitmap(evt))
	require.Nil(t, s.GetAllRulesBitmap(evt))
}
