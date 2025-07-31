package dependencies

import (
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
)

func getTestDependenciesFunc(deps map[events.ID]events.Dependencies) func(events.ID) events.Dependencies {
	return func(id events.ID) events.Dependencies {
		return deps[id]
	}
}

func TestManager_AddEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		eventToAdd events.ID
		deps       map[events.ID]events.Dependencies
	}{
		{
			name:       "empty dependency",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): {},
			},
		},
		{
			name:       "dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): {},
			},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessExit, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
		},
	}

	t.Run("Sanity", func(t *testing.T) {
		t.Parallel()

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				// Create a new Manager instance
				m := NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

				var eventsAdditions []events.ID
				m.SubscribeAdd(
					EventNodeType,
					func(node interface{}) []Action {
						newEventNode, ok := node.(*EventNode)
						require.True(t, ok)
						eventsAdditions = append(eventsAdditions, newEventNode.GetID())
						return nil
					},
				)

				// Check that multiple selects are not causing any issues
				for i := 0; i < 3; i++ {
					_, err := m.SelectEvent(testCase.eventToAdd)
					require.NoError(t, err)

					depProbes := make(map[probes.Handle][]events.ID)
					for id, expDep := range testCase.deps {
						evtNode, err := m.GetEvent(id)
						assert.NoError(t, err)
						dep := evtNode.GetDependencies()
						assert.ElementsMatch(t, expDep.GetIDs(), dep.GetIDs())

						for _, probe := range dep.GetProbes() {
							depProbes[probe.GetHandle()] = append(
								depProbes[probe.GetHandle()],
								id,
							)
						}

						// Test dependencies building
						for _, dependency := range dep.GetIDs() {
							dependencyNode, err := m.GetEvent(dependency)
							assert.NoError(t, err)
							dependents := dependencyNode.GetDependents()
							assert.Contains(t, dependents, id)
						}

						// Test addition watcher logic
						assert.Contains(t, eventsAdditions, id)
					}
					for handle, ids := range depProbes {
						probeNode, err := m.GetProbe(handle)
						require.NoError(t, err, handle)
						assert.ElementsMatch(t, ids, probeNode.GetDependents())
					}
				}
			},
			)
		}
	})
	t.Run("Add cancel", func(t *testing.T) {
		t.Parallel()

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				// Create a new Manager instance
				m := NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

				var eventsAdditions, eventsRemove []events.ID
				// Count additions
				m.SubscribeAdd(
					EventNodeType,
					func(node interface{}) []Action {
						newEventNode, ok := node.(*EventNode)
						require.True(t, ok)
						eventsAdditions = append(eventsAdditions, newEventNode.GetID())
						return nil
					},
				)

				// Count removes
				m.SubscribeRemove(
					EventNodeType,
					func(node interface{}) []Action {
						removeEventNode, ok := node.(*EventNode)
						require.True(t, ok)
						eventsRemove = append(eventsRemove, removeEventNode.GetID())
						return nil
					},
				)

				// Cancel event add
				m.SubscribeAdd(
					EventNodeType,
					func(node interface{}) []Action {
						newEventNode, ok := node.(*EventNode)
						require.True(t, ok)
						if newEventNode.GetID() == testCase.eventToAdd {
							return []Action{NewCancelNodeAddAction(errors.New("fail"))}
						}
						return nil
					},
				)

				_, err := m.SelectEvent(testCase.eventToAdd)
				require.IsType(t, &ErrNodeAddCancelled{}, err)

				// Check that all the dependencies were cancelled
				depProbes := make(map[probes.Handle][]events.ID)
				for id := range testCase.deps {
					_, err := m.GetEvent(id)
					assert.ErrorIs(t, err, ErrNodeNotFound, id)
				}
				for handle := range depProbes {
					_, err := m.GetProbe(handle)
					assert.ErrorIs(t, err, ErrNodeNotFound, handle)
				}
				_, err = m.GetEvent(testCase.eventToAdd)
				assert.ErrorIs(t, err, ErrNodeNotFound, testCase.eventToAdd)
				assert.Len(t, eventsAdditions, len(testCase.deps))
				assert.Len(t, eventsRemove, len(testCase.deps))
				assert.ElementsMatch(t, eventsAdditions, eventsRemove)
			},
			)
		}
	})
}

func TestManager_RemoveEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                  string
		preAddedEvents        []events.ID
		eventToAdd            events.ID
		deps                  map[events.ID]events.Dependencies
		expectedRemovedEvents []events.ID
	}{
		{
			name:       "empty dependency",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1)},
		},
		{
			name:       "dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessExit, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2), events.ID(3)},
		},
		{
			name:           "multi dependency event but is dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(1)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessFork, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessExit, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2), events.ID(3), events.ID(4)},
		},
		{
			name:           "multi dependency event that share dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessExit, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Create a new Manager instance
			m := NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

			var eventsRemoved []events.ID
			m.SubscribeRemove(
				EventNodeType,
				func(node interface{}) []Action {
					removedEvtNode, ok := node.(*EventNode)
					require.True(t, ok)
					eventsRemoved = append(eventsRemoved, removedEvtNode.GetID())
					return nil
				})

			for _, preAddedEvent := range testCase.preAddedEvents {
				_, err := m.SelectEvent(preAddedEvent)
				require.NoError(t, err)
			}

			_, err := m.SelectEvent(testCase.eventToAdd)
			require.NoError(t, err)

			expectedDepProbes := make(map[probes.Handle][]events.ID)
			for id, expDep := range testCase.deps {
				if slices.Contains(testCase.expectedRemovedEvents, id) {
					continue
				}
				for _, probe := range expDep.GetProbes() {
					expectedDepProbes[probe.GetHandle()] = append(expectedDepProbes[probe.GetHandle()], id)
				}
			}

			// Check that multiple removes are not causing any issues
			for i := 0; i < 3; i++ {
				err := m.RemoveEvent(testCase.eventToAdd)
				if i == 0 {
					require.NoError(t, err)
				} else {
					assert.ErrorIs(t, err, ErrNodeNotFound, testCase.name)
				}

				for _, id := range testCase.expectedRemovedEvents {
					_, err := m.GetEvent(id)
					assert.Error(t, err)

					// Test indirect addition watcher logic
					assert.Contains(t, eventsRemoved, id)
				}

				for handle, ids := range expectedDepProbes {
					probeNode, err := m.GetProbe(handle)
					require.NoError(t, err, handle)
					assert.ElementsMatch(t, ids, probeNode.GetDependents())
				}
			}
		})
	}
}

func TestManager_UnselectEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                  string
		preAddedEvents        []events.ID
		eventToAdd            events.ID
		deps                  map[events.ID]events.Dependencies
		expectedRemovedEvents []events.ID
	}{
		{
			name:       "empty dependency",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1)},
		},
		{
			name:       "dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2), events.ID(3)},
		},
		{
			name:           "multi dependency event but is dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(1)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{},
		},
		{
			name:           "multi dependency event that share dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessFork, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessExit, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Create a new Manager instance
			m := NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

			var eventsRemoved []events.ID
			m.SubscribeRemove(
				EventNodeType,
				func(node interface{}) []Action {
					removedEvtNode, ok := node.(*EventNode)
					require.True(t, ok)
					eventsRemoved = append(eventsRemoved, removedEvtNode.GetID())
					return nil
				})

			for _, preAddedEvent := range testCase.preAddedEvents {
				_, err := m.SelectEvent(preAddedEvent)
				require.NoError(t, err)
			}

			_, err := m.SelectEvent(testCase.eventToAdd)
			require.NoError(t, err)

			// Check that multiple unselects are not causing any issues
			for i := 0; i < 3; i++ {
				m.UnselectEvent(testCase.eventToAdd)

				for _, id := range testCase.expectedRemovedEvents {
					_, err := m.GetEvent(id)
					assert.Error(t, err)

					// Test indirect addition watcher logic
					assert.Contains(t, eventsRemoved, id)
				}
			}
		})
	}
}

func TestManager_FailEvent(t *testing.T) {
	testCases := []struct {
		name                   string
		preAddedEvents         []events.ID
		eventToAdd             events.ID
		deps                   map[events.ID]events.Dependencies
		expectedRemovedEvents  []events.ID
		expectedExistingEvents map[events.ID][]events.ID
		expectEventRemoved     bool
	}{
		{
			name:       "no dependencies with no fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): {},
			},
			expectedRemovedEvents:  []events.ID{events.ID(1)},
			expectedExistingEvents: map[events.ID][]events.ID{},
			expectEventRemoved:     true,
		},
		{
			name:       "no dependencies with empty fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependenciesWithFallbacks(
					[]events.ID{},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.Dependencies{{}},
				),
			},
			expectedRemovedEvents: []events.ID{},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {},
			},
			expectEventRemoved: false,
		},
		{
			name:       "no dependencies with fallback with dependencies",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependenciesWithFallbacks(
					[]events.ID{},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.Dependencies{
						events.NewDependencies(
							[]events.ID{2},
							nil,
							nil,
							nil,
							events.Capabilities{},
						),
					},
				),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {2},
				2: {},
			},
			expectEventRemoved: false,
		},
		{
			name:       "event with dependency with empty dependency fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependenciesWithFallbacks(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.Dependencies{{}},
				),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(2)},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {},
			},
			expectEventRemoved: false,
		},
		{
			name:       "event with multiple dependencies without fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents:  []events.ID{events.ID(1), events.ID(2), events.ID(3)},
			expectedExistingEvents: map[events.ID][]events.ID{},
			expectEventRemoved:     true,
		},
		{
			name:       "event with fallback event with dependencies",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependenciesWithFallbacks(
					[]events.ID{},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.Dependencies{
						events.NewDependencies(
							[]events.ID{2},
							nil,
							nil,
							nil,
							events.Capabilities{},
						),
					},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {2},
				2: {3},
				3: {},
			},
			expectEventRemoved: false,
		},
		{
			name:           "multi levels dependency event with no fallback which is a dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(1)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents:  []events.ID{1, 2, 3, 4},
			expectedExistingEvents: map[events.ID][]events.ID{},
			expectEventRemoved:     true,
		},
		{
			name:           "multi levels dependency event with no fallback which shares dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessFork, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
						events.NewProbe(probes.SchedProcessExit, true),
					},
					nil,
					events.Capabilities{},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
			expectedExistingEvents: map[events.ID][]events.ID{
				4: {3},
				3: {},
			},
			expectEventRemoved: true,
		},
		{
			name:       "event with multiple fallbacks available",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependenciesWithFallbacks(
					[]events.ID{events.ID(2)}, // Primary dependency
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.Dependencies{
						// First fallback - depends on event 3
						events.NewDependencies(
							[]events.ID{events.ID(3)},
							nil,
							nil,
							nil,
							events.Capabilities{},
						),
						// Second fallback - empty dependencies
						{},
					},
				),
				events.ID(2): {},
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(2)},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {3}, // First fallback will be used
				3: {},
			},
			expectEventRemoved: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create a new Manager instance
			m := NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

			var eventsRemove []events.ID

			// Count removes
			m.SubscribeRemove(
				EventNodeType,
				func(node interface{}) []Action {
					removeEventNode, ok := node.(*EventNode)
					require.True(t, ok)
					eventsRemove = append(eventsRemove, removeEventNode.GetID())
					return nil
				},
			)

			for _, preAddedEvent := range testCase.preAddedEvents {
				_, err := m.SelectEvent(preAddedEvent)
				require.NoError(t, err)
			}

			_, err := m.SelectEvent(testCase.eventToAdd)
			require.NoError(t, err)

			// Call FailEvent
			removed, err := m.FailEvent(testCase.eventToAdd)
			require.NoError(t, err)

			// Check if event was removed as expected
			assert.Equal(t, testCase.expectEventRemoved, removed)

			// Verify removed events
			for _, id := range testCase.expectedRemovedEvents {
				_, err := m.GetEvent(events.ID(id))
				assert.ErrorIs(t, err, ErrNodeNotFound, "Event %d should be removed", id)
				assert.Contains(t, eventsRemove, events.ID(id), "Event %d should be in removed list", id)
			}

			// Verify existing events and their dependencies
			for id, expectedDeps := range testCase.expectedExistingEvents {
				node, err := m.GetEvent(events.ID(id))
				require.NoError(t, err, "Event %d should exist", id)

				actualDeps := node.GetDependencies().GetIDs()
				assert.ElementsMatch(t, expectedDeps, actualDeps, "Event %d dependencies mismatch", id)

				// Verify it's not in removed list
				assert.NotContains(t, eventsRemove, events.ID(id), "Event %d should not be removed", id)
			}
		})
	}
}

func TestManager_FailEvent_MultipleFallbacks(t *testing.T) {
	// Test to demonstrate first fallback failing, second succeeding
	// We'll use an add watcher to cancel the first fallback dependency

	deps := map[events.ID]events.Dependencies{
		events.ID(1): events.NewDependenciesWithFallbacks(
			[]events.ID{events.ID(2)}, // Primary dependency
			nil,
			nil,
			nil,
			events.Capabilities{},
			[]events.Dependencies{
				// First fallback - depends on event 3 (will be cancelled)
				events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				// Second fallback - depends on event 4 (will succeed)
				events.NewDependencies(
					[]events.ID{events.ID(4)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
			},
		),
		events.ID(2): {},
		events.ID(3): {},
		events.ID(4): {},
	}

	m := NewDependenciesManager(getTestDependenciesFunc(deps))

	// Add watcher that cancels event 3 addition (dependent event 1 will fail and use next fallback)
	m.SubscribeAdd(
		EventNodeType,
		func(node interface{}) []Action {
			newEventNode, ok := node.(*EventNode)
			if !ok {
				return nil
			}
			if newEventNode.GetID() == events.ID(3) {
				return []Action{NewCancelNodeAddAction(errors.New("event 3 cancelled"))}
			}
			return nil
		},
	)

	var eventsRemove []events.ID
	m.SubscribeRemove(EventNodeType, func(node interface{}) []Action {
		eventsRemove = append(eventsRemove, node.(*EventNode).GetID())
		return nil
	})

	// Add event successfully with primary dependencies
	_, err := m.SelectEvent(events.ID(1))
	require.NoError(t, err)

	// Verify primary dependency exists
	node, err := m.GetEvent(events.ID(1))
	require.NoError(t, err)
	assert.Equal(t, []events.ID{events.ID(2)}, node.GetDependencies().GetIDs())

	// Call FailEvent - should try first fallback (fails due to cancellation), then second fallback (succeeds)
	removed, err := m.FailEvent(events.ID(1))
	require.NoError(t, err)
	assert.False(t, removed) // Event should not be removed

	// Verify event now uses second fallback (depends on event 4)
	node, err = m.GetEvent(events.ID(1))
	require.NoError(t, err)
	assert.Equal(t, []events.ID{events.ID(4)}, node.GetDependencies().GetIDs())

	// Verify event 4 exists
	_, err = m.GetEvent(events.ID(4))
	require.NoError(t, err)

	// Verify original dependency (event 2) was removed
	assert.Contains(t, eventsRemove, events.ID(2))
}

func TestManager_FailureVsCancellation(t *testing.T) {
	t.Run("FailNodeAddAction triggers fallbacks", func(t *testing.T) {
		deps := map[events.ID]events.Dependencies{
			events.ID(1): events.NewDependenciesWithFallbacks(
				[]events.ID{events.ID(2)}, // Primary dependency
				nil,
				nil,
				nil,
				events.Capabilities{},
				[]events.Dependencies{
					// Fallback - empty dependencies
					{},
				},
			),
			events.ID(2): {},
		}

		m := NewDependenciesManager(getTestDependenciesFunc(deps))

		// Add watcher that fails (not cancels) event 2 addition
		m.SubscribeAdd(
			EventNodeType,
			func(node interface{}) []Action {
				newEventNode, ok := node.(*EventNode)
				if !ok {
					return nil
				}
				if newEventNode.GetID() == events.ID(1) {
					return []Action{NewFailNodeAddAction(errors.New("event 1 failed"))}
				}
				return nil
			},
		)

		// Try to add event 1 - should succeed using fallback when event 2 fails
		eventNode, err := m.SelectEvent(events.ID(1))
		require.NoError(t, err)
		assert.NotNil(t, eventNode)

		// Verify event 1 uses fallback (empty dependencies)
		assert.Empty(t, eventNode.GetDependencies().GetIDs())

		// Verify event 2 was not added
		_, err = m.GetEvent(events.ID(2))
		assert.ErrorIs(t, err, ErrNodeNotFound)
	})

	t.Run("CancelNodeAddAction causes immediate removal", func(t *testing.T) {
		deps := map[events.ID]events.Dependencies{
			events.ID(1): events.NewDependenciesWithFallbacks(
				[]events.ID{events.ID(2)}, // Primary dependency
				nil,
				nil,
				nil,
				events.Capabilities{},
				[]events.Dependencies{},
			),
			events.ID(2): {},
		}

		m := NewDependenciesManager(getTestDependenciesFunc(deps))

		var eventsRemove []events.ID
		m.SubscribeRemove(EventNodeType, func(node interface{}) []Action {
			eventNode, ok := node.(*EventNode)
			if !ok {
				return nil
			}
			eventsRemove = append(eventsRemove, eventNode.GetID())
			return nil
		})

		// Add watcher that cancels event 2 addition
		m.SubscribeAdd(
			EventNodeType,
			func(node interface{}) []Action {
				newEventNode, ok := node.(*EventNode)
				if !ok {
					return nil
				}
				if newEventNode.GetID() == events.ID(2) {
					return []Action{NewCancelNodeAddAction(errors.New("event 2 cancelled"))}
				}
				return nil
			},
		)

		// Try to add event 1 - should fail because dependency was cancelled and no fallbacks work
		_, err := m.SelectEvent(events.ID(1))
		require.Error(t, err)

		// Should be a failed error (converted from cancellation) since this is a dependent event
		var failErr *ErrNodeAddFailed
		assert.True(t, errors.As(err, &failErr))

		// Verify neither event was added
		_, err = m.GetEvent(events.ID(1))
		assert.ErrorIs(t, err, ErrNodeNotFound)
		_, err = m.GetEvent(events.ID(2))
		assert.ErrorIs(t, err, ErrNodeNotFound)
	})

	t.Run("Dependent event uses fallback when dependency is cancelled", func(t *testing.T) {
		deps := map[events.ID]events.Dependencies{
			events.ID(1): events.NewDependenciesWithFallbacks(
				[]events.ID{events.ID(2)}, // Primary dependency
				nil,
				nil,
				nil,
				events.Capabilities{},
				[]events.Dependencies{
					// Fallback - depends on event 3
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					),
				},
			),
			events.ID(2): {},
			events.ID(3): {},
		}

		m := NewDependenciesManager(getTestDependenciesFunc(deps))

		// Add watcher that cancels event 2 addition
		m.SubscribeAdd(
			EventNodeType,
			func(node interface{}) []Action {
				newEventNode, ok := node.(*EventNode)
				if !ok {
					return nil
				}
				if newEventNode.GetID() == events.ID(2) {
					return []Action{NewCancelNodeAddAction(errors.New("event 2 cancelled"))}
				}
				return nil
			},
		)

		// Try to add event 1 - should succeed using fallback when event 2 is cancelled
		eventNode, err := m.SelectEvent(events.ID(1))
		require.NoError(t, err)
		assert.NotNil(t, eventNode)

		// Verify event 1 uses fallback (depends on event 3)
		assert.Equal(t, []events.ID{events.ID(3)}, eventNode.GetDependencies().GetIDs())

		// Verify event 3 was added
		_, err = m.GetEvent(events.ID(3))
		assert.NoError(t, err)

		// Verify event 2 was not added
		_, err = m.GetEvent(events.ID(2))
		assert.ErrorIs(t, err, ErrNodeNotFound)
	})
}

func TestManager_FailEvent_ProbeFailures(t *testing.T) {
	// Test basic FailEvent functionality without mocking
	deps := map[events.ID]events.Dependencies{
		events.ID(1): events.NewDependenciesWithFallbacks(
			[]events.ID{},
			nil,
			[]events.Probe{events.NewProbe(probes.SchedProcessExec, true)},
			nil,
			events.Capabilities{},
			[]events.Dependencies{
				events.NewDependencies(
					[]events.ID{},
					nil,
					[]events.Probe{events.NewProbe(probes.SchedProcessExit, true)},
					nil,
					events.Capabilities{},
				),
			},
		),
	}

	m := NewDependenciesManager(getTestDependenciesFunc(deps))

	// Add event successfully
	_, err := m.SelectEvent(events.ID(1))
	require.NoError(t, err)

	// Verify event exists with primary dependencies
	node, err := m.GetEvent(events.ID(1))
	require.NoError(t, err)

	primaryProbes := node.GetDependencies().GetProbes()
	require.Len(t, primaryProbes, 1)
	assert.Equal(t, probes.SchedProcessExec, primaryProbes[0].GetHandle())

	// Test FailEvent on existing event with fallbacks
	removed, err := m.FailEvent(events.ID(1))
	require.NoError(t, err)

	// Since we can't mock probe failures, the fallback should succeed
	// (empty dependencies build successfully)
	assert.False(t, removed) // Event should not be removed

	// Verify event still exists after FailEvent
	_, err = m.GetEvent(events.ID(1))
	require.NoError(t, err)
}

func TestManager_FailEvent_NonExistentEvent(t *testing.T) {
	m := NewDependenciesManager(getTestDependenciesFunc(map[events.ID]events.Dependencies{}))

	// Try to fail an event that doesn't exist
	removed, err := m.FailEvent(events.ID(999))
	require.ErrorIs(t, err, ErrNodeNotFound)
	assert.False(t, removed)
}

func TestManager_FailEvent_EventWithoutFallbacks(t *testing.T) {
	deps := map[events.ID]events.Dependencies{
		events.ID(1): events.NewDependencies(
			[]events.ID{events.ID(2)},
			nil,
			[]events.Probe{events.NewProbe(probes.SchedProcessExec, true)},
			nil,
			events.Capabilities{},
		),
		events.ID(2): {},
	}

	m := NewDependenciesManager(getTestDependenciesFunc(deps))

	var removedEvents []events.ID
	m.SubscribeRemove(EventNodeType, func(node interface{}) []Action {
		removedEvents = append(removedEvents, node.(*EventNode).GetID())
		return nil
	})

	// Add event
	_, err := m.SelectEvent(events.ID(1))
	require.NoError(t, err)

	// Fail event (no fallbacks available)
	removed, err := m.FailEvent(events.ID(1))
	require.NoError(t, err)
	assert.True(t, removed) // Event should be removed

	// Verify event and its dependencies are removed
	_, err = m.GetEvent(events.ID(1))
	assert.ErrorIs(t, err, ErrNodeNotFound)
	_, err = m.GetEvent(events.ID(2))
	assert.ErrorIs(t, err, ErrNodeNotFound)

	// Verify removal events were triggered
	assert.Contains(t, removedEvents, events.ID(1))
	assert.Contains(t, removedEvents, events.ID(2))
}
