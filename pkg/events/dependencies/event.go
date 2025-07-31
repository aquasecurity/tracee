package dependencies

import (
	"slices"

	"github.com/aquasecurity/tracee/pkg/events"
)

// EventNode represent an event in the dependencies tree.
// It should be read-only for other packages, as it is internally managed.
type EventNode struct {
	id                   events.ID
	explicitlySelected   bool
	originalDependencies events.Dependencies // The original dependencies from event definition
	activeDependencies   events.Dependencies // Currently active dependencies (may be a fallback)
	currentFallbackIndex int                 // Index of current fallback (-1 means using primary dependencies)
	// There won't be more than a couple of dependents, so a slice is better for
	// both performance and supporting efficient thread-safe operation in the future
	dependents []events.ID
}

func newDependenciesNode(id events.ID, dependencies events.Dependencies, chosenDirectly bool) *EventNode {
	return &EventNode{
		id:                   id,
		explicitlySelected:   chosenDirectly,
		originalDependencies: dependencies,
		activeDependencies:   dependencies,
		currentFallbackIndex: -1, // -1 means using primary dependencies
		dependents:           make([]events.ID, 0),
	}
}

func (en *EventNode) GetID() events.ID {
	return en.id
}

func (en *EventNode) GetDependencies() events.Dependencies {
	return en.activeDependencies
}

// hasMoreFallbacks returns true if there are more fallback dependency sets to try
func (en *EventNode) hasMoreFallbacks() bool {
	fallbacks := en.originalDependencies.GetFallbacks()
	return en.currentFallbackIndex+1 < len(fallbacks)
}

// fallback switches to the next available fallback dependency set
// Returns true if successful, false if no more fallbacks available
func (en *EventNode) fallback() bool {
	if !en.hasMoreFallbacks() {
		return false
	}

	en.currentFallbackIndex++
	fallback, exists := en.originalDependencies.GetFallbackAt(en.currentFallbackIndex)
	if !exists {
		return false
	}

	en.activeDependencies = fallback
	return true
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
