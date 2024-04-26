package dependencies

import (
	"slices"

	"github.com/aquasecurity/tracee/pkg/events"
)

// EventNode represent an event in the dependencies tree.
// It should be read-only for other packages, as it is internally managed.
type EventNode struct {
	id                 events.ID
	explicitlySelected bool
	dependencies       events.Dependencies
	// There won't be more than a couple of dependants, so a slice is better for
	// both performance and supporting efficient thread-safe operation in the future
	dependants []events.ID
}

func newDependenciesNode(id events.ID, dependencies events.Dependencies, chosenDirectly bool) *EventNode {
	return &EventNode{
		id:                 id,
		explicitlySelected: chosenDirectly,
		dependencies:       dependencies,
		dependants:         make([]events.ID, 0),
	}
}

func (en *EventNode) GetID() events.ID {
	return en.id
}

func (en *EventNode) GetDependencies() events.Dependencies {
	return en.dependencies
}

func (en *EventNode) GetDependants() []events.ID {
	return slices.Clone[[]events.ID](en.dependants)
}

func (en *EventNode) IsDependencyOf(dependant events.ID) bool {
	for _, d := range en.dependants {
		if d == dependant {
			return true
		}
	}
	return false
}

func (en *EventNode) isExplicitlySelected() bool {
	return en.explicitlySelected
}

func (en *EventNode) markAsExplicitlySelected() {
	en.explicitlySelected = true
}

func (en *EventNode) unmarkAsExplicitlySelected() {
	en.explicitlySelected = false
}

func (en *EventNode) addDependant(dependant events.ID) {
	en.dependants = append(en.dependants, dependant)
}

func (en *EventNode) removeDependant(dependant events.ID) {
	for i, d := range en.dependants {
		if d == dependant {
			en.dependants = append(en.dependants[:i], en.dependants[i+1:]...)
			break
		}
	}
}
