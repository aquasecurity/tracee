package dependencies

import "github.com/aquasecurity/tracee/pkg/events"

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

func (n *EventNode) GetID() events.ID {
	return n.id
}

func (n *EventNode) GetDependencies() events.Dependencies {
	return n.dependencies
}

func (n *EventNode) GetDependants() []events.ID {
	return n.dependants
}

func (n *EventNode) IsDependencyOf(dependant events.ID) bool {
	for _, d := range n.dependants {
		if d == dependant {
			return true
		}
	}
	return false
}

func (n *EventNode) isExplicitlySelected() bool {
	return n.explicitlySelected
}

func (n *EventNode) markAsExplicitlySelected() {
	n.explicitlySelected = true
}

func (n *EventNode) unmarkAsExplicitlySelected() {
	n.explicitlySelected = false
}

func (n *EventNode) addDependant(dependant events.ID) {
	n.dependants = append(n.dependants, dependant)
}

func (n *EventNode) removeDependant(dependant events.ID) {
	for i, d := range n.dependants {
		if d == dependant {
			n.dependants = append(n.dependants[:i], n.dependants[i+1:]...)
			break
		}
	}
}
