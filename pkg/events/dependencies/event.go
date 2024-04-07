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
	// There won't be more than a couple of dependents, so a slice is better for
	// both performance and supporting efficient thread-safe operation in the future
	dependents      []events.ID
	currentFallback int // The index of current fallback dependencies
}

func newDependenciesNode(id events.ID, dependencies events.Dependencies, chosenDirectly bool) *EventNode {
	return &EventNode{
		id:                 id,
		explicitlySelected: chosenDirectly,
		dependencies:       dependencies,
		dependents:         make([]events.ID, 0),
		currentFallback:    -1,
	}
}

func (en *EventNode) GetID() events.ID {
	return en.id
}

func (en *EventNode) GetDependencies() events.Dependencies {
	if en.currentFallback < 0 {
		return en.dependencies
	}
	fallbacks := en.dependencies.GetFallbacks()
	return fallbacks[en.currentFallback].GetDependencies()
}

func (en *EventNode) GetDependents() []events.ID {
	return slices.Clone[[]events.ID](en.dependents)
}

func (en *EventNode) IsDependencyOf(dependent events.ID) bool {
	for _, d := range en.dependents {
		if d == dependent {
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

func (en *EventNode) addDependent(dependent events.ID) {
	en.dependents = append(en.dependents, dependent)
}

func (en *EventNode) removeDependent(dependent events.ID) {
	for i, d := range en.dependents {
		if d == dependent {
			en.dependents = append(en.dependents[:i], en.dependents[i+1:]...)
			break
		}
	}
}

func (en *EventNode) fallback() bool {
	fallbacks := en.dependencies.GetFallbacks()
	if (en.currentFallback + 1) >= len(fallbacks) {
		return false
	}
	en.currentFallback += 1
	return true
}

func (en *EventNode) clone() *EventNode {
	clone := &EventNode{
		id:                 en.id,
		explicitlySelected: en.explicitlySelected,
		dependencies:       en.dependencies,
		dependents:         slices.Clone[[]events.ID](en.dependents),
	}
	return clone
}
