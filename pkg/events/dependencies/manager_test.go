package dependencies_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
)

func getTestDependenciesFunc(deps map[events.ID]events.Dependencies) func(events.ID) events.Dependencies {
	return func(id events.ID) events.Dependencies {
		return deps[id]
	}
}

func TestManager_AddEvent(t *testing.T) {
	testCases := []struct {
		name                 string
		eventToAdd           events.ID
		deps                 map[events.ID]events.Dependencies
		fallbackKeptEvents   []events.ID
		fallbackUniqueEvents []events.ID
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
					nil,
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
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
		},
		{
			name:       "event with a fallback",
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
					[]events.DependenciesFallback{
						events.NewDependenciesFallback(
							events.NewDependencies(
								[]events.ID{events.ID(4)},
								nil,
								[]events.Probe{
									events.NewProbe(probes.SchedProcessFork, true),
								},
								nil,
								events.Capabilities{},
								nil,
							),
						),
					},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
				events.ID(4): {},
			},
			fallbackKeptEvents:   []events.ID{events.ID(1), events.ID(4)},
			fallbackUniqueEvents: []events.ID{events.ID(4)},
		},
	}

	t.Run("Sanity", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				// Create a new Manager instance
				m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))
				var eventsAdditions []events.ID
				m.SubscribeAdd(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						newEventNode := node.(*dependencies.EventNode)
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
						if slices.Contains(testCase.fallbackUniqueEvents, id) {
							assert.ErrorIs(t, err, dependencies.ErrNodeNotFound, id)
							continue
						}
						assert.NoError(t, err, id)
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
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				// Create a new Manager instance
				m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))
				var eventsAdditions, eventsRemove []events.ID
				// Count additions
				m.SubscribeAdd(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						newEventNode := node.(*dependencies.EventNode)
						eventsAdditions = append(eventsAdditions, newEventNode.GetID())
						return nil
					},
				)

				// Count removes
				m.SubscribeRemove(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						removeEventNode := node.(*dependencies.EventNode)
						eventsRemove = append(eventsRemove, removeEventNode.GetID())
						return nil
					},
				)

				// Cancel event add
				m.SubscribeAdd(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						newEventNode := node.(*dependencies.EventNode)
						if newEventNode.GetID() == testCase.eventToAdd {
							return []dependencies.Action{dependencies.NewCancelNodeAddAction(errors.New("fail"))}
						}
						return nil
					},
				)

				fallbacks := testCase.deps[testCase.eventToAdd].GetFallbacks()
				_, err := m.SelectEvent(testCase.eventToAdd)
				if fallbacks != nil {
					require.NoError(t, err)
				} else {
					require.IsType(t, &dependencies.ErrNodeAddCancelled{}, err)
				}
				// Check that all the dependencies were cancelled
				var removedDepProbes, addedDepProbes []probes.Handle
				for id, deps := range testCase.deps {
					_, err = m.GetEvent(id)
					// If the event is kept after failed event moved to fallback
					if slices.Contains(testCase.fallbackKeptEvents, id) {
						assert.NoError(t, err, id)
						depProbes := deps.GetProbes()
						// The added event moved to fallback, so use it instead
						if id == testCase.eventToAdd {
							depProbes = fallbacks[len(fallbacks)-1].GetDependencies().GetProbes()
						}
						for _, probe := range depProbes {
							addedDepProbes = append(addedDepProbes, probe.GetHandle())
						}
					} else {
						assert.ErrorIs(t, err, dependencies.ErrNodeNotFound, id)
						for _, probe := range deps.GetProbes() {
							removedDepProbes = append(removedDepProbes, probe.GetHandle())
						}
					}
				}
				for _, handle := range removedDepProbes {
					if slices.Contains(addedDepProbes, handle) {
						continue
					}
					_, err := m.GetProbe(handle)
					assert.ErrorIs(t, err, dependencies.ErrNodeNotFound, handle)
				}

				for _, handle := range addedDepProbes {
					_, err := m.GetProbe(handle)
					assert.NoError(t, err, handle)
				}
				// TODO: Test additions and removes with fallbacks
				if fallbacks == nil {
					assert.Len(t, eventsAdditions, len(testCase.deps))
					assert.Len(t, eventsRemove, len(testCase.deps))
					assert.ElementsMatch(t, eventsAdditions, eventsRemove)
				}
			},
			)
		}
	})
}

func TestManager_RemoveEvent(t *testing.T) {
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
					nil,
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
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
					nil,
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
					nil,
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
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					[]events.Probe{
						events.NewProbe(probes.SchedProcessExec, true),
					},
					nil,
					events.Capabilities{},
					nil,
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
					nil,
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
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
	}
	for _, testCase := range testCases {
		t.Run(
			testCase.name, func(t *testing.T) {
				// Create a new Manager instance
				m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

				var eventsRemoved []events.ID
				m.SubscribeRemove(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						removedEvtNode := node.(*dependencies.EventNode)
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
						assert.ErrorIs(t, err, dependencies.ErrNodeNotFound, testCase.name)
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
					nil,
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
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
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
					nil,
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
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
					nil,
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
		},
	}
	for _, testCase := range testCases {
		t.Run(
			testCase.name, func(t *testing.T) {
				// Create a new Manager instance
				m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

				var eventsRemoved []events.ID
				m.SubscribeRemove(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						removedEvtNode := node.(*dependencies.EventNode)
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
	}{
		{
			name:       "no dependencies with no fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): {},
			},
			expectedRemovedEvents:  []events.ID{events.ID(1)},
			expectedExistingEvents: map[events.ID][]events.ID{},
		},
		{
			name:       "no dependencies with empty fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.DependenciesFallback{
						events.NewDependenciesFallback(events.Dependencies{}),
					},
				),
			},
			expectedRemovedEvents: []events.ID{},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {},
			},
		},
		{
			name:       "no dependencies with fallback with dependencies",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.DependenciesFallback{
						events.NewDependenciesFallback(
							events.NewDependencies(
								[]events.ID{2},
								nil,
								nil,
								nil,
								events.Capabilities{},
								nil,
							),
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
		},
		{
			name:       "event with dependency with empty dependency fallback",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.DependenciesFallback{
						events.NewDependenciesFallback(events.Dependencies{}),
					},
				),
				events.ID(2): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(2)},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {},
			},
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
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
			expectedRemovedEvents:  []events.ID{events.ID(1), events.ID(2), events.ID(3)},
			expectedExistingEvents: map[events.ID][]events.ID{},
		},
		{
			name:       "event with fallback event with dependencies",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies(
					[]events.ID{},
					nil,
					nil,
					nil,
					events.Capabilities{},
					[]events.DependenciesFallback{
						events.NewDependenciesFallback(
							events.NewDependencies(
								[]events.ID{2},
								nil,
								nil,
								nil,
								events.Capabilities{},
								nil,
							),
						),
					},
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{},
			expectedExistingEvents: map[events.ID][]events.ID{
				1: {2},
				2: {3},
				3: {},
			},
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
					nil,
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
			expectedRemovedEvents:  []events.ID{1, 2, 3, 4},
			expectedExistingEvents: map[events.ID][]events.ID{},
		},
		{
			name:           "multi levels dependency event with no fallback which shares dependency",
			eventToAdd:     events.ID(1),
			preAddedEvents: []events.ID{events.ID(4)},
			deps: map[events.ID]events.Dependencies{
				events.ID(4): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(1): events.NewDependencies(
					[]events.ID{events.ID(2)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(2): events.NewDependencies(
					[]events.ID{events.ID(3)},
					nil,
					nil,
					nil,
					events.Capabilities{},
					nil,
				),
				events.ID(3): {},
			},
			expectedRemovedEvents: []events.ID{events.ID(1), events.ID(2)},
			expectedExistingEvents: map[events.ID][]events.ID{
				4: {3},
				3: {},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(
			testCase.name, func(t *testing.T) {
				// Create a new Manager instance
				m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

				var eventsRemove []events.ID

				// Count removes
				m.SubscribeRemove(
					dependencies.EventNodeType,
					func(node interface{}) []dependencies.Action {
						removeEventNode := node.(*dependencies.EventNode)
						eventsRemove = append(eventsRemove, removeEventNode.GetID())
						return nil
					},
				)

				hasChanged := false
				// Count removes
				m.SubscribeChange(
					dependencies.EventNodeType,
					func(previousNode interface{}, newNode interface{}) []dependencies.Action {
						hasChanged = true
						return nil
					},
				)

				for _, preAddedEvent := range testCase.preAddedEvents {
					_, err := m.SelectEvent(preAddedEvent)
					require.NoError(t, err)
				}

				_, err := m.SelectEvent(testCase.eventToAdd)
				require.NoError(t, err)

				removed, err := m.FailEvent(testCase.eventToAdd)
				require.NoError(t, err)
				if slices.Contains(testCase.expectedRemovedEvents, testCase.eventToAdd) {
					assert.True(t, removed)
				} else {
					assert.False(t, removed)
					assert.True(t, hasChanged)
				}

				for _, id := range testCase.expectedRemovedEvents {
					_, err := m.GetEvent(id)
					assert.ErrorIs(t, err, dependencies.ErrNodeNotFound, id)

					// Test indirect addition watcher logic
					assert.Contains(t, eventsRemove, id)
				}

				for id, deps := range testCase.expectedExistingEvents {
					node, err := m.GetEvent(id)
					require.NoError(t, err, id)

					assert.ElementsMatch(t, deps, node.GetDependencies().GetIDs(), id)

					// Test indirect addition watcher logic
					assert.NotContains(t, eventsRemove, id)
				}
			})
	}
}
