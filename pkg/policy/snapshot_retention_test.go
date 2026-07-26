package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
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

// Test_Snapshot_PushedVersion_Window guards B2: during the window between a policy mutation and
// its kernel push (and permanently if the push fails), the snapshot's rules are a newer
// generation than its exported filter maps. The net-event userland scope pass must key the
// exported maps by the PUSHED version (what the kernel/exportedFMaps actually hold), not the
// current rules version - otherwise it looks up a version the maps don't have, misses, and
// silently disables all net-event scope narrowing.
func Test_Snapshot_PushedVersion_Window(t *testing.T) {
	const evt = events.ID(60200)

	pm := &PolicyManager{
		rules:          map[events.ID]EventRules{evt: buildEventRules(&EventRule{ID: 0, Policy: &Policy{Name: "p"}, SelectionType: SelectedByUser})},
		pushedVersions: map[events.ID]uint16{},
	}
	// Model the mutation-before-push window: rules advanced to version 5, but the kernel + the
	// exported maps are still at the previously-pushed version 4.
	er := pm.rules[evt]
	er.rulesVersion = 5
	pm.rules[evt] = er
	pm.pushedVersions[evt] = 4
	pm.publishSnapshot()

	s := pm.LoadSnapshot()
	require.Equal(t, uint16(5), s.GetRulesVersion(evt), "rules version is the new generation")
	require.Equal(t, uint16(4), s.GetPushedVersion(evt),
		"net scope must key exported maps by the PUSHED version (what the kernel holds), not the newer rules version")

	// Before anything is pushed for an event, GetPushedVersion falls back to the rules version
	// (init, no in-flight events yet).
	const fresh = events.ID(60201)
	pm.rules[fresh] = buildEventRules(&EventRule{ID: 0, Policy: &Policy{Name: "q"}, SelectionType: SelectedByUser})
	er2 := pm.rules[fresh]
	er2.rulesVersion = 1
	pm.rules[fresh] = er2
	pm.publishSnapshot()
	require.Equal(t, uint16(1), pm.LoadSnapshot().GetPushedVersion(fresh),
		"no pushed version yet => fall back to the rules version")
}

// Test_Snapshot_DisabledRules_NoInPlaceMutation guards B1: a rebuild (AddPolicy/RemovePolicy)
// must never mutate the disabledRules backing array of an already-published snapshot. Before the
// deepCopyEventRules slice copy, assignStableRuleIDs pruned the shared array in place - a data
// race on the lock-free read path and a retroactive re-enable of a disabled rule in in-flight
// events. Run under -race to catch the concurrent-read variant.
func Test_Snapshot_DisabledRules_NoInPlaceMutation(t *testing.T) {
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	newRuleData := func(id events.ID) RuleData {
		return RuleData{EventID: id, ScopeFilter: filters.NewScopeFilter(), DataFilter: filters.NewDataFilter(), RetFilter: filters.NewIntFilter()}
	}

	p1 := NewPolicy()
	p1.Name = "p1"
	p1.Rules = map[events.ID]RuleData{events.Openat: newRuleData(events.Openat)}
	pm, err := NewManager(ManagerConfig{}, depsManager, p1)
	require.NoError(t, err)
	require.NoError(t, pm.DisableRule("p1", events.Openat))

	// Capture the snapshot the way an in-flight event does, and read its disabled bitmap.
	s := pm.LoadSnapshot()
	before := append([]uint64(nil), s.GetDisabledRules(events.Openat)...)
	require.NotEmpty(t, before, "guard: p1's rule is disabled in the captured snapshot")

	// A concurrent reader hammers the captured snapshot's disabled bitmap while an unrelated
	// policy is added/removed (each triggers a rebuild). Under -race, an in-place mutation of
	// the shared backing array is a reported race.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.GetDisabledRules(events.Openat)
			}
		}
	}()
	for i := 0; i < 20; i++ {
		p2 := NewPolicy()
		p2.Name = "p2"
		p2.Rules = map[events.ID]RuleData{events.Openat: newRuleData(events.Openat)}
		require.NoError(t, pm.AddPolicy(p2))
		require.NoError(t, pm.RemovePolicy("p2"))
	}
	close(stop)

	// The captured snapshot's disabled bitmap must be unchanged by the rebuilds.
	require.Equal(t, before, s.GetDisabledRules(events.Openat),
		"a rebuild mutated an already-published snapshot's disabledRules backing array")
}
