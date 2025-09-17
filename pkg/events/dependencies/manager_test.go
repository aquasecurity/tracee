package dependencies

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
)

func getTestDependenciesFunc(deps map[events.ID]events.DependencyStrategy) func(events.ID) events.DependencyStrategy {
	return func(id events.ID) events.DependencyStrategy {
		return deps[id]
	}
}

func TestManager_AddEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		eventToAdd events.ID
		deps       map[events.ID]events.DependencyStrategy
	}{
		{
			name:       "empty dependency",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): {},
			},
		},
		{
			name:       "dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): {},
			},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessExit, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(3): {},
			},
		},
		{
			name:       "dependency event with tailcall",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						[]events.TailCall{
							events.NewTailCall("vfs_write", "vfs_write", []uint32{2, 3}),
						},
						events.Capabilities{},
					)),
				events.ID(2): {},
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
					depTailCalls := make(map[string]events.TailCall)
					for id, expDep := range testCase.deps {
						evtNode, err := m.GetEvent(id)
						assert.NoError(t, err)
						dep := evtNode.GetDependencies()
						assert.ElementsMatch(t, expDep.GetPrimaryDependencies().GetIDs(), dep.GetIDs())

						// Verify probe dependencies are correctly set up
						for _, probe := range dep.GetProbes() {
							depProbes[probe.GetHandle()] = append(
								depProbes[probe.GetHandle()],
								id,
							)
						}

						// Verify tailcall dependencies are correctly set up
						for _, tailCall := range dep.GetTailCalls() {
							depTailCalls[GetTCKey(tailCall)] = tailCall
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

					// Verify probe nodes are created and have correct dependents
					for handle, ids := range depProbes {
						probeNode, err := m.GetProbe(handle)
						require.NoError(t, err, "Probe %v should exist", handle)
						assert.ElementsMatch(t, ids, probeNode.GetDependents(), "Probe %v should have correct dependents", handle)
					}

					// Verify tailcall nodes are created and have correct dependents
					for key, tailCall := range depTailCalls {
						tailCallNode, err := m.GetTailCall(GetTCKey(tailCall))
						require.NoError(t, err, "Tailcall %v should exist", key)
						assert.Equal(t, key, GetTCKey(tailCallNode.GetTailCall()))
						assert.ElementsMatch(t, tailCall.GetIndexes(), tailCallNode.GetTailCall().GetIndexes(), "Tailcall %v should have correct indexes", key)
					}

					// Verify that no extra probes exist beyond what's expected
					allProbes := m.GetProbes()
					expectedProbeHandles := make([]probes.Handle, 0, len(depProbes))
					for handle := range depProbes {
						expectedProbeHandles = append(expectedProbeHandles, handle)
					}
					assert.ElementsMatch(t, expectedProbeHandles, allProbes, "Manager should only contain expected probes")
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
				for id, expDep := range testCase.deps {
					_, err := m.GetEvent(id)
					assert.ErrorIs(t, err, ErrNodeNotFound, id)

					// Collect expected probes for verification
					for _, probe := range expDep.GetPrimaryDependencies().GetProbes() {
						depProbes[probe.GetHandle()] = append(depProbes[probe.GetHandle()], id)
					}
				}

				// Verify all expected probes were also removed
				for handle := range depProbes {
					_, err := m.GetProbe(handle)
					assert.ErrorIs(t, err, ErrNodeNotFound, "Probe %v should be removed after cancellation", handle)
				}

				// Verify no probes remain in the manager
				allProbes := m.GetProbes()
				assert.Empty(t, allProbes, "No probes should remain after event cancellation")
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
		deps                  map[events.ID]events.DependencyStrategy
		expectedRemovedEvents []events.ID
	}{
		{
			name:       "empty dependency",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1)},
		},
		{
			name:       "dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessExit, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2), events.ID(3)},
		},
		{
			name:           "multi dependency event but is dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(4): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(1)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessFork, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessExit, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2), events.ID(3), events.ID(4)},
		},
		{
			name:           "multi dependency event that share dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(4): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessExit, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
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
			removedProbes := make(map[probes.Handle]struct{})

			// Calculate expected remaining probes and removed probes
			for id, expDep := range testCase.deps {
				for _, probe := range expDep.GetPrimaryDependencies().GetProbes() {
					if slices.Contains(testCase.expectedRemovedEvents, id) {
						// This probe dependency is being removed
						removedProbes[probe.GetHandle()] = struct{}{}
					} else {
						// This probe dependency should remain
						expectedDepProbes[probe.GetHandle()] = append(expectedDepProbes[probe.GetHandle()], id)
					}
				}
			}

			// Remove probes that still have dependents from the removed list
			for handle, ids := range expectedDepProbes {
				if len(ids) > 0 {
					delete(removedProbes, handle)
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

				// Verify expected events are removed
				for _, id := range testCase.expectedRemovedEvents {
					_, err := m.GetEvent(id)
					assert.Error(t, err, "Event %d should be removed", id)

					// Test indirect addition watcher logic
					assert.Contains(t, eventsRemoved, id)
				}

				// Verify expected probes still exist with correct dependents
				for handle, ids := range expectedDepProbes {
					probeNode, err := m.GetProbe(handle)
					require.NoError(t, err, "Probe %v should still exist", handle)
					assert.ElementsMatch(t, ids, probeNode.GetDependents(), "Probe %v should have correct remaining dependents", handle)
				}

				// Verify removed probes no longer exist
				for handle := range removedProbes {
					_, err := m.GetProbe(handle)
					assert.ErrorIs(t, err, ErrNodeNotFound, "Probe %v should be removed", handle)
				}

				// Verify manager contains only expected probes
				allProbes := m.GetProbes()
				expectedProbeHandles := slices.Collect(maps.Keys(expectedDepProbes))
				assert.ElementsMatch(t, expectedProbeHandles, allProbes, "Manager should only contain expected probes after removal")
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
		deps                  map[events.ID]events.DependencyStrategy
		expectedRemovedEvents []events.ID
	}{
		{
			name:       "empty dependency",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1)},
		},
		{
			name:       "dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2), events.ID(3)},
		},
		{
			name:           "multi dependency event but is dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(4): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(1)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{},
		},
		{
			name:           "multi dependency event that share dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(4): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessFork, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessExit, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
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

			// Calculate expected remaining and removed probes
			expectedDepProbes := make(map[probes.Handle][]events.ID)
			removedProbes := make(map[probes.Handle]struct{})

			for id, expDep := range testCase.deps {
				for _, probe := range expDep.GetPrimaryDependencies().GetProbes() {
					if slices.Contains(testCase.expectedRemovedEvents, id) {
						// This probe dependency will be removed
						removedProbes[probe.GetHandle()] = struct{}{}
					} else {
						// This probe dependency should remain
						expectedDepProbes[probe.GetHandle()] = append(expectedDepProbes[probe.GetHandle()], id)
					}
				}
			}

			// Remove probes that still have dependents from the removed list
			for handle, ids := range expectedDepProbes {
				if len(ids) > 0 {
					delete(removedProbes, handle)
				}
			}

			// Check that multiple unselects are not causing any issues
			for i := 0; i < 3; i++ {
				m.UnselectEvent(testCase.eventToAdd)

				// Verify expected events are removed
				for _, id := range testCase.expectedRemovedEvents {
					_, err := m.GetEvent(id)
					assert.Error(t, err, "Event %d should be removed after unselect", id)

					// Test indirect addition watcher logic
					assert.Contains(t, eventsRemoved, id)
				}

				// Verify expected probes still exist with correct dependents
				for handle, ids := range expectedDepProbes {
					probeNode, err := m.GetProbe(handle)
					require.NoError(t, err, "Probe %v should still exist after unselect", handle)
					assert.ElementsMatch(t, ids, probeNode.GetDependents(), "Probe %v should have correct remaining dependents", handle)
				}

				// Verify removed probes no longer exist
				for handle := range removedProbes {
					_, err := m.GetProbe(handle)
					assert.ErrorIs(t, err, ErrNodeNotFound, "Probe %v should be removed after unselect", handle)
				}

				// Verify manager contains only expected probes
				allProbes := m.GetProbes()
				expectedProbeHandles := slices.Collect(maps.Keys(expectedDepProbes))
				assert.ElementsMatch(t, expectedProbeHandles, allProbes, "Manager should only contain expected probes after unselect")
			}
		})
	}
}

func TestManager_FailEvent(t *testing.T) {
	testCases := []struct {
		name                   string
		preAddedEvents         []events.ID
		eventToAdd             events.ID
		deps                   map[events.ID]events.DependencyStrategy
		expectedRemovedEvents  []events.ID
		expectedExistingEvents map[events.ID][]events.ID
		expectEventRemoved     bool
	}{
		{
			name:       "no dependencies with no fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): {},
			},
			expectedRemovedEvents:  []events.ID{events.ID(1)},
			expectedExistingEvents: map[events.ID][]events.ID{},
			expectEventRemoved:     true,
		},
		{
			name:       "no dependencies with empty fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{events.ID(2)}, // Primary dependency that will fail
						nil,
						nil,
						nil,
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // Empty fallback
							[]events.ID{},
							nil,
							nil,
							nil,
							events.Capabilities{},
						),
					},
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
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{events.ID(3)}, // Primary dependency that will fail
						nil,
						nil,
						nil,
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // Fallback with dependencies
							[]events.ID{events.ID(2)},
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
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{events.ID(2)}, // Primary dependency
						nil,
						nil,
						nil,
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // Empty fallback
							[]events.ID{},
							nil,
							nil,
							nil,
							events.Capabilities{},
						),
					},
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
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(3): {},
			},
			expectedRemovedEvents:  []events.ID{events.ID(1), events.ID(2), events.ID(3)},
			expectedExistingEvents: map[events.ID][]events.ID{},
			expectEventRemoved:     true,
		},
		{
			name:       "event with fallback event with dependencies",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{events.ID(4)}, // Primary dependency that will fail
						nil,
						nil,
						nil,
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // Fallback to event 2
							[]events.ID{events.ID(2)},
							nil,
							nil,
							nil,
							events.Capabilities{},
						),
					},
				),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
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
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(4): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(1)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
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
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(4): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessFork, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
							events.NewProbe(probes.SchedProcessExit, true),
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(3)},
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
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
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{events.ID(2)}, // Primary dependency
						nil,
						nil,
						nil,
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // First fallback
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
		{
			name:       "event with tailcall dependency without fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "failing_handler", []uint32{1}),
						},
						events.Capabilities{},
					),
				),
			},
			expectedRemovedEvents:  []events.ID{events.ID(1)},
			expectedExistingEvents: map[events.ID][]events.ID{},
			expectEventRemoved:     true,
		},
		{
			name:       "event with tailcall dependency with fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "failing_handler", []uint32{1}),
						},
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // Fallback with different tailcall
							[]events.ID{},
							nil,
							[]events.Probe{},
							[]events.TailCall{
								events.NewTailCall("prog_array", "fallback_handler", []uint32{2}),
							},
							events.Capabilities{},
						),
					},
				),
			},
			expectedRemovedEvents: []events.ID{},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {}, // Event preserved using fallback
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

			// Calculate expected probe state after failure
			expectedActiveProbes := make(map[probes.Handle][]events.ID)
			removedProbes := make(map[probes.Handle]struct{})
			expectedActiveTailcalls := make(map[string][]events.ID)

			// Collect probes from existing events (those using current dependencies)
			for id, expectedDeps := range testCase.expectedExistingEvents {
				node, err := m.GetEvent(events.ID(id))
				require.NoError(t, err, "Event %d should exist", id)

				actualDeps := node.GetDependencies().GetIDs()
				assert.ElementsMatch(t, expectedDeps, actualDeps, "Event %d dependencies mismatch", id)

				// Collect probes from current (possibly fallback) dependencies
				for _, probe := range node.GetDependencies().GetProbes() {
					expectedActiveProbes[probe.GetHandle()] = append(expectedActiveProbes[probe.GetHandle()], events.ID(id))
				}

				// Collect tailcalls from current (possibly fallback) dependencies
				for _, tailcall := range node.GetDependencies().GetTailCalls() {
					tcKey := GetTCKey(tailcall)
					expectedActiveTailcalls[tcKey] = append(expectedActiveTailcalls[tcKey], events.ID(id))
				}

				// Verify it's not in removed list
				assert.NotContains(t, eventsRemove, events.ID(id), "Event %d should not be removed", id)
			}

			// Collect probes from removed events (should be cleaned up if no other dependents)
			for _, id := range testCase.expectedRemovedEvents {
				if dep, exists := testCase.deps[events.ID(id)]; exists {
					for _, probe := range dep.GetPrimaryDependencies().GetProbes() {
						// Mark as potentially removed (will be filtered out if still has dependents)
						removedProbes[probe.GetHandle()] = struct{}{}
					}
				}
			}

			// Remove probes that still have active dependents
			for handle, deps := range expectedActiveProbes {
				if len(deps) > 0 {
					delete(removedProbes, handle)
				}
			}

			// Verify expected probes exist with correct dependents
			for handle, expectedDeps := range expectedActiveProbes {
				probeNode, err := m.GetProbe(handle)
				require.NoError(t, err, "Probe %v should exist after event failure", handle)
				assert.ElementsMatch(t, expectedDeps, probeNode.GetDependents(), "Probe %v should have correct dependents", handle)
			}

			// Verify removed probes no longer exist
			for handle := range removedProbes {
				_, err := m.GetProbe(handle)
				assert.ErrorIs(t, err, ErrNodeNotFound, "Probe %v should be removed after event failure", handle)
			}

			// Verify manager contains only expected probes
			allProbes := m.GetProbes()
			expectedProbeHandles := slices.Collect(maps.Keys(expectedActiveProbes))
			assert.ElementsMatch(t, expectedProbeHandles, allProbes, "Manager should only contain expected probes after event failure")
		})
	}
}

func TestManager_FailEvent_MultipleFallbacks(t *testing.T) {
	// Test to demonstrate first fallback failing, second succeeding
	// We'll use an add watcher to cancel the first fallback dependency

	deps := map[events.ID]events.DependencyStrategy{
		events.ID(1): events.NewDependencyStrategyWithFallbacks(
			events.NewDependencies(
				[]events.ID{events.ID(2)}, // Primary dependency
				nil,
				nil,
				nil,
				events.Capabilities{},
			),
			[]events.Dependencies{
				events.NewDependencies( // First fallback - depends on event 3 (will be cancelled)
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				events.NewDependencies( // Second fallback - depends on event 4 (will succeed)
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

	// Verify probe state after fallback switch
	// Event 1 should no longer have any probe dependencies (second fallback has no probes)
	currentProbes := node.GetDependencies().GetProbes()
	assert.Empty(t, currentProbes, "Event 1 should have no probe dependencies after using second fallback")

	// Verify no probes remain in the manager (since original probes should be cleaned up)
	allProbes := m.GetProbes()
	assert.Empty(t, allProbes, "All probes should be removed after fallback switch")
}

func TestManager_FailureVsCancellation(t *testing.T) {
	t.Run("FailNodeAddAction triggers fallbacks", func(t *testing.T) {
		deps := map[events.ID]events.DependencyStrategy{
			events.ID(1): events.NewDependencyStrategyWithFallbacks(
				events.NewDependencies(
					[]events.ID{events.ID(2)}, // Primary dependency
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
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

		// Verify event 1 has no probe dependencies in fallback
		assert.Empty(t, eventNode.GetDependencies().GetProbes())

		// Verify event 2 was not added
		_, err = m.GetEvent(events.ID(2))
		assert.ErrorIs(t, err, ErrNodeNotFound)

		// Verify no probes were added since fallback has no dependencies
		allProbes := m.GetProbes()
		assert.Empty(t, allProbes, "No probes should exist when using empty fallback")
	})

	t.Run("CancelNodeAddAction causes immediate removal", func(t *testing.T) {
		deps := map[events.ID]events.DependencyStrategy{
			events.ID(1): events.NewDependencyStrategy(
				events.NewDependencies(
					[]events.ID{events.ID(2)}, // Primary dependency
					nil,
					nil,
					nil,
					events.Capabilities{},
				)),
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
		deps := map[events.ID]events.DependencyStrategy{
			events.ID(1): events.NewDependencyStrategyWithFallbacks(
				events.NewDependencies(
					[]events.ID{events.ID(2)}, // Primary dependency
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
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

		// Verify event 1 has no probe dependencies in fallback
		assert.Empty(t, eventNode.GetDependencies().GetProbes(), "Fallback should have no probe dependencies")

		// Verify event 3 was added
		_, err = m.GetEvent(events.ID(3))
		assert.NoError(t, err)

		// Verify event 2 was not added
		_, err = m.GetEvent(events.ID(2))
		assert.ErrorIs(t, err, ErrNodeNotFound)

		// Verify no probes exist since fallback has no probe dependencies
		allProbes := m.GetProbes()
		assert.Empty(t, allProbes, "No probes should exist when fallback has no probe dependencies")
	})

	t.Run("Direct event cancellation removes event instead of using fallbacks", func(t *testing.T) {
		deps := map[events.ID]events.DependencyStrategy{
			events.ID(1): events.NewDependencyStrategyWithFallbacks(
				events.NewDependencies(
					[]events.ID{events.ID(2)}, // Primary dependency
					nil,
					nil,
					nil,
					events.Capabilities{},
				),
				[]events.Dependencies{
					// Valid fallback - empty dependencies (should work)
					{},
				},
			),
			events.ID(2): {},
		}

		m := NewDependenciesManager(getTestDependenciesFunc(deps))

		var eventsRemoved []events.ID
		m.SubscribeRemove(EventNodeType, func(node interface{}) []Action {
			eventNode, ok := node.(*EventNode)
			if !ok {
				return nil
			}
			eventsRemoved = append(eventsRemoved, eventNode.GetID())
			return nil
		})

		// Add watcher that directly cancels event 1 (not its dependencies)
		m.SubscribeAdd(
			EventNodeType,
			func(node interface{}) []Action {
				newEventNode, ok := node.(*EventNode)
				if !ok {
					return nil
				}
				if newEventNode.GetID() == events.ID(1) {
					return []Action{NewCancelNodeAddAction(errors.New("event 1 directly cancelled"))}
				}
				return nil
			},
		)

		// Try to add event 1 - should fail because the event itself is cancelled
		// Even though it has valid fallback dependencies, cancellation should cause immediate removal
		_, err := m.SelectEvent(events.ID(1))
		require.Error(t, err)

		// Should be a cancellation error since this is the directly cancelled event
		var cancelErr *ErrNodeAddCancelled
		assert.True(t, errors.As(err, &cancelErr))

		// Verify event 1 was removed (should be in removal list)
		assert.Contains(t, eventsRemoved, events.ID(1))

		// Verify event 1 is not in the tree
		_, err = m.GetEvent(events.ID(1))
		assert.ErrorIs(t, err, ErrNodeNotFound)

		// Verify event 2 was also not added (since event 1 was cancelled before dependencies were built)
		_, err = m.GetEvent(events.ID(2))
		assert.ErrorIs(t, err, ErrNodeNotFound)

		// Verify no probes were added since event was cancelled before dependencies were built
		allProbes := m.GetProbes()
		assert.Empty(t, allProbes, "No probes should exist after direct event cancellation")
	})
}

func TestManager_FailEvent_ProbeFailures(t *testing.T) {
	// Test basic FailEvent functionality without mocking
	deps := map[events.ID]events.DependencyStrategy{
		events.ID(1): events.NewDependencyStrategyWithFallbacks(
			events.NewDependencies(
				[]events.ID{},
				nil,
				[]events.Probe{events.NewProbe(probes.SchedProcessExec, true)},
				nil,
				events.Capabilities{},
			),
			[]events.Dependencies{
				events.NewDependencies(
					[]events.ID{},
					nil,
					[]events.Probe{events.NewProbe(probes.SchedProcessExit, true)},
					nil,
					events.Capabilities{},
				),
			},
		)}

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
	m := NewDependenciesManager(getTestDependenciesFunc(map[events.ID]events.DependencyStrategy{}))

	// Try to fail an event that doesn't exist
	removed, err := m.FailEvent(events.ID(999))
	require.ErrorIs(t, err, ErrNodeNotFound)
	assert.False(t, removed)
}

func TestManager_FailEvent_EventWithoutFallbacks(t *testing.T) {
	deps := map[events.ID]events.DependencyStrategy{
		events.ID(1): events.NewDependencyStrategy(
			events.NewDependencies(
				[]events.ID{events.ID(2)},
				nil,
				[]events.Probe{events.NewProbe(probes.SchedProcessExec, true)},
				nil,
				events.Capabilities{},
			)),
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

func TestManager_FailProbe(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                    string
		preAddedEvents          []events.ID
		deps                    map[events.ID]events.DependencyStrategy
		probeToFail             probes.Handle
		expectedRemovedEvents   []events.ID
		expectedPreservedEvents []events.ID
		expectedError           bool
	}{
		{
			name: "non-required probe failure doesn't fail event",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, false), // non-required
						},
						nil,
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{},
			expectedPreservedEvents: []events.ID{events.ID(1)},
			expectedError:           false,
		},
		{
			name: "required probe failure fails event",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true), // required
						},
						nil,
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{events.ID(1)},
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "probe with multiple dependent events - mixed required/non-required",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true), // required
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, false), // non-required
						},
						nil,
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1), events.ID(2)},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{events.ID(1)}, // only required probe event fails
			expectedPreservedEvents: []events.ID{events.ID(2)}, // non-required probe event preserved
			expectedError:           false,
		},
		{
			name: "required probe failure with event having fallbacks",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true), // required primary
						},
						nil,
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // fallback with different probe
							[]events.ID{},
							nil,
							[]events.Probe{
								events.NewProbe(probes.SchedProcessExit, true),
							},
							nil,
							events.Capabilities{},
						),
					},
				),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{},
			expectedPreservedEvents: []events.ID{events.ID(1)}, // event preserved using fallback
			expectedError:           false,
		},
		{
			name: "required probe failure with event having no usable fallbacks",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true), // required
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): {},
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{events.ID(1), events.ID(2)}, // event and dependencies removed
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "cascading failures from probe failure",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true), // required
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExit, true), // different probe
						},
						nil,
						events.Capabilities{},
					)),
				events.ID(3): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(1)}, // depends on event 1
						nil,
						nil,
						nil,
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1), events.ID(3)},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{events.ID(1), events.ID(2), events.ID(3)}, // cascading removal
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "multiple probes on same event - only required probe fails event",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),  // required
							events.NewProbe(probes.SchedProcessExit, false), // non-required
							events.NewProbe(probes.SchedProcessFork, true),  // required
						},
						nil,
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			probeToFail:             probes.SchedProcessExit, // fail the non-required one
			expectedRemovedEvents:   []events.ID{},
			expectedPreservedEvents: []events.ID{events.ID(1)}, // event preserved
			expectedError:           false,
		},
		{
			name:                    "non-existent probe failure",
			deps:                    map[events.ID]events.DependencyStrategy{},
			preAddedEvents:          []events.ID{},
			probeToFail:             probes.SchedProcessExec,
			expectedRemovedEvents:   []events.ID{},
			expectedPreservedEvents: []events.ID{},
			expectedError:           false, // Should handle gracefully
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
					removedEventNode, ok := node.(*EventNode)
					require.True(t, ok)
					eventsRemoved = append(eventsRemoved, removedEventNode.GetID())
					return nil
				})

			// Add pre-existing events
			for _, eventID := range testCase.preAddedEvents {
				_, err := m.SelectEvent(eventID)
				require.NoError(t, err, "Failed to add pre-existing event %d", eventID)
			}

			// Verify all events exist before probe failure
			for _, eventID := range testCase.preAddedEvents {
				_, err := m.GetEvent(eventID)
				require.NoError(t, err, "Event %d should exist before probe failure", eventID)
			}

			// Fail the probe
			err := m.FailProbe(testCase.probeToFail)
			if testCase.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check removed events
			for _, expectedRemovedEvent := range testCase.expectedRemovedEvents {
				_, err := m.GetEvent(expectedRemovedEvent)
				assert.ErrorIs(t, err, ErrNodeNotFound, "Event %d should be removed", expectedRemovedEvent)
				assert.Contains(t, eventsRemoved, expectedRemovedEvent, "Event %d should be in removed list", expectedRemovedEvent)
			}

			// Check preserved events
			for _, expectedPreservedEvent := range testCase.expectedPreservedEvents {
				_, err := m.GetEvent(expectedPreservedEvent)
				assert.NoError(t, err, "Event %d should be preserved", expectedPreservedEvent)
				assert.NotContains(t, eventsRemoved, expectedPreservedEvent, "Event %d should not be in removed list", expectedPreservedEvent)
			}

			// Test multiple failures of the same probe (should be idempotent)
			err = m.FailProbe(testCase.probeToFail)
			require.NoError(t, err, "Multiple probe failures should be handled gracefully")

			// State should remain the same after second failure
			for _, expectedRemovedEvent := range testCase.expectedRemovedEvents {
				_, err := m.GetEvent(expectedRemovedEvent)
				assert.ErrorIs(t, err, ErrNodeNotFound, "Event %d should still be removed after second probe failure", expectedRemovedEvent)
			}

			for _, expectedPreservedEvent := range testCase.expectedPreservedEvents {
				_, err := m.GetEvent(expectedPreservedEvent)
				assert.NoError(t, err, "Event %d should still be preserved after second probe failure", expectedPreservedEvent)
			}
		})
	}
}

func TestManager_FailTailCall(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                    string
		preAddedEvents          []events.ID
		deps                    map[events.ID]events.DependencyStrategy
		tailCallToFail          events.TailCall
		expectedRemovedEvents   []events.ID
		expectedPreservedEvents []events.ID
		expectedError           bool
	}{
		{
			name: "tailcall failure fails event (tailcalls always required)",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "handler_a", []uint32{1}),
						},
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			tailCallToFail:          events.NewTailCall("prog_array", "handler_a", []uint32{1}),
			expectedRemovedEvents:   []events.ID{events.ID(1)},
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "tailcall with multiple dependent events",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "shared_handler", []uint32{1}),
						},
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "shared_handler", []uint32{2}),
						},
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1), events.ID(2)},
			tailCallToFail:          events.NewTailCall("prog_array", "shared_handler", []uint32{}), // Key doesn't include indexes
			expectedRemovedEvents:   []events.ID{events.ID(1), events.ID(2)},                        // Both fail since tailcall is required
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "tailcall failure with event having fallbacks",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategyWithFallbacks(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "primary_handler", []uint32{1}),
						},
						events.Capabilities{},
					),
					[]events.Dependencies{
						events.NewDependencies( // Fallback with different tailcall
							[]events.ID{},
							nil,
							[]events.Probe{},
							[]events.TailCall{
								events.NewTailCall("prog_array", "fallback_handler", []uint32{2}),
							},
							events.Capabilities{},
						),
					},
				),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			tailCallToFail:          events.NewTailCall("prog_array", "primary_handler", []uint32{}),
			expectedRemovedEvents:   []events.ID{},
			expectedPreservedEvents: []events.ID{events.ID(1)}, // Event preserved using fallback
			expectedError:           false,
		},
		{
			name: "tailcall failure with event having no usable fallbacks",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "handler", []uint32{1}),
						},
						events.Capabilities{},
					)),
				events.ID(2): {},
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			tailCallToFail:          events.NewTailCall("prog_array", "handler", []uint32{}),
			expectedRemovedEvents:   []events.ID{events.ID(1), events.ID(2)}, // Event and dependencies removed
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "cascading failures from tailcall failure",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(2)},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "handler_a", []uint32{1}),
						},
						events.Capabilities{},
					)),
				events.ID(2): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{},
						[]events.TailCall{
							events.NewTailCall("prog_array", "handler_b", []uint32{2}), // Different tailcall
						},
						events.Capabilities{},
					)),
				events.ID(3): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{events.ID(1)}, // Depends on event 1
						nil,
						[]events.Probe{},
						nil,
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1), events.ID(3)},
			tailCallToFail:          events.NewTailCall("prog_array", "handler_a", []uint32{}),
			expectedRemovedEvents:   []events.ID{events.ID(1), events.ID(2), events.ID(3)}, // Cascading removal
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name: "mixed dependencies - tailcall and probe failures",
			deps: map[events.ID]events.DependencyStrategy{
				events.ID(1): events.NewDependencyStrategy(
					events.NewDependencies(
						[]events.ID{},
						nil,
						[]events.Probe{
							events.NewProbe(probes.SchedProcessExec, true),
						},
						[]events.TailCall{
							events.NewTailCall("prog_array", "handler", []uint32{1}),
						},
						events.Capabilities{},
					)),
			},
			preAddedEvents:          []events.ID{events.ID(1)},
			tailCallToFail:          events.NewTailCall("prog_array", "handler", []uint32{}),
			expectedRemovedEvents:   []events.ID{events.ID(1)},
			expectedPreservedEvents: []events.ID{},
			expectedError:           false,
		},
		{
			name:                    "non-existent tailcall failure",
			deps:                    map[events.ID]events.DependencyStrategy{},
			preAddedEvents:          []events.ID{},
			tailCallToFail:          events.NewTailCall("prog_array", "nonexistent", []uint32{}),
			expectedRemovedEvents:   []events.ID{},
			expectedPreservedEvents: []events.ID{},
			expectedError:           false, // Should handle gracefully
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
					removedEventNode, ok := node.(*EventNode)
					require.True(t, ok)
					eventsRemoved = append(eventsRemoved, removedEventNode.GetID())
					return nil
				})

			// Add pre-existing events
			for _, eventID := range testCase.preAddedEvents {
				_, err := m.SelectEvent(eventID)
				require.NoError(t, err, "Failed to add pre-existing event %d", eventID)
			}

			// Verify all events exist before tailcall failure
			for _, eventID := range testCase.preAddedEvents {
				_, err := m.GetEvent(eventID)
				require.NoError(t, err, "Event %d should exist before tailcall failure", eventID)
			}

			// Fail the tailcall
			err := m.FailTailCall(testCase.tailCallToFail)
			if testCase.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check removed events
			for _, expectedRemovedEvent := range testCase.expectedRemovedEvents {
				_, err := m.GetEvent(expectedRemovedEvent)
				assert.ErrorIs(t, err, ErrNodeNotFound, "Event %d should be removed", expectedRemovedEvent)
				assert.Contains(t, eventsRemoved, expectedRemovedEvent, "Event %d should be in removed list", expectedRemovedEvent)
			}

			// Check preserved events
			for _, expectedPreservedEvent := range testCase.expectedPreservedEvents {
				_, err := m.GetEvent(expectedPreservedEvent)
				assert.NoError(t, err, "Event %d should be preserved", expectedPreservedEvent)
				assert.NotContains(t, eventsRemoved, expectedPreservedEvent, "Event %d should not be in removed list", expectedPreservedEvent)
			}

			// Verify tailcalls are cleaned up properly
			allTailCalls := m.GetTailCalls()
			for _, key := range allTailCalls {
				tailCallNode, err := m.GetTailCall(key)
				require.NoError(t, err)
				// Verify each remaining tailcall has at least one dependent
				assert.NotEmpty(t, tailCallNode.GetDependents(), "Tailcall %s should have dependents", key)
			}

			// Test multiple failures of the same tailcall (should be idempotent)
			err = m.FailTailCall(testCase.tailCallToFail)
			require.NoError(t, err, "Multiple tailcall failures should be handled gracefully")

			// State should remain the same after second failure
			for _, expectedRemovedEvent := range testCase.expectedRemovedEvents {
				_, err := m.GetEvent(expectedRemovedEvent)
				assert.ErrorIs(t, err, ErrNodeNotFound, "Event %d should still be removed after second tailcall failure", expectedRemovedEvent)
			}

			for _, expectedPreservedEvent := range testCase.expectedPreservedEvents {
				_, err := m.GetEvent(expectedPreservedEvent)
				assert.NoError(t, err, "Event %d should still be preserved after second tailcall failure", expectedPreservedEvent)
			}
		})
	}
}

func TestManager_StateChangeWatcher_TailcallMerge(t *testing.T) {
	deps := map[events.ID]events.DependencyStrategy{
		events.ID(1): events.NewDependencyStrategy(
			events.NewDependencies(
				[]events.ID{},
				nil,
				[]events.Probe{},
				[]events.TailCall{
					events.NewTailCall("prog_array", "handler", []uint32{1, 2}),
				},
				events.Capabilities{},
			)),
		events.ID(2): events.NewDependencyStrategy(
			events.NewDependencies(
				[]events.ID{},
				nil,
				[]events.Probe{},
				[]events.TailCall{
					events.NewTailCall("prog_array", "handler", []uint32{3, 4}),
				},
				events.Capabilities{},
			)),
	}

	m := NewDependenciesManager(getTestDependenciesFunc(deps))

	// Add first event
	_, err := m.SelectEvent(events.ID(1))
	require.NoError(t, err)

	// Add second event with same tailcall map+prog but different indexes
	_, err = m.SelectEvent(events.ID(2))
	require.NoError(t, err)

	// Verify merged indexes
	tailCallNode, err := m.GetTailCall(GetTCKey(events.NewTailCall("prog_array", "handler", []uint32{})))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint32{1, 2, 3, 4}, tailCallNode.GetTailCall().GetIndexes())
}
