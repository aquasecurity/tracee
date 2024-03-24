package dependencies_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
				events.ID(1): events.NewDependencies([]events.ID{events.ID(2)}, nil, nil, nil, events.Capabilities{}),
				events.ID(2): {},
			},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies([]events.ID{events.ID(2)}, nil, nil, nil, events.Capabilities{}),
				events.ID(2): events.NewDependencies([]events.ID{events.ID(3)}, nil, nil, nil, events.Capabilities{}),
				events.ID(3): {},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create a new Manager instance
			m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))
			var indirectAdditions []events.ID
			m.SubscribeIndirectAdd(
				func(newEvtID events.ID) {
					indirectAdditions = append(indirectAdditions, newEvtID)
				})

			m.AddEvent(testCase.eventToAdd)

			for id, expDep := range testCase.deps {
				dep, ok := m.GetEvent(id)
				assert.True(t, ok)
				assert.ElementsMatch(t, expDep.GetIDs(), dep.GetIDs())

				// Test dependencies building
				for _, dependency := range dep.GetIDs() {
					dependants, ok := m.GetDependantEvents(dependency)
					assert.True(t, ok)
					assert.Contains(t, dependants, id)
				}

				// Test indirect addition watcher logic
				if id == testCase.eventToAdd {
					assert.NotContains(t, indirectAdditions, id)
				} else {
					assert.Contains(t, indirectAdditions, id)
				}
			}
		})
	}
}

func TestManager_RemoveEvent(t *testing.T) {
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
				events.ID(1): events.NewDependencies([]events.ID{events.ID(2)}, nil, nil, nil, events.Capabilities{}),
				events.ID(2): {},
			},
		},
		{
			name:       "multi dependency event",
			eventToAdd: events.ID(1),
			deps: map[events.ID]events.Dependencies{
				events.ID(1): events.NewDependencies([]events.ID{events.ID(2)}, nil, nil, nil, events.Capabilities{}),
				events.ID(2): events.NewDependencies([]events.ID{events.ID(3)}, nil, nil, nil, events.Capabilities{}),
				events.ID(3): {},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create a new Manager instance
			m := dependencies.NewDependenciesManager(getTestDependenciesFunc(testCase.deps))

			var indirectRemoves []events.ID
			m.SubscribeIndirectRemove(
				func(removedId events.ID) {
					indirectRemoves = append(indirectRemoves, removedId)
				})

			m.AddEvent(testCase.eventToAdd)

			m.RemoveEvent(testCase.eventToAdd)

			for id := range testCase.deps {
				_, ok := m.GetEvent(id)
				assert.False(t, ok)

				// Test indirect addition watcher logic
				if id == testCase.eventToAdd {
					assert.NotContains(t, indirectRemoves, id)
				} else {
					assert.Contains(t, indirectRemoves, id)
				}
			}
		})
	}
}
