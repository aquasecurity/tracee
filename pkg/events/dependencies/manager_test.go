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
