package dependencies

import "github.com/aquasecurity/tracee/pkg/events"

type Node struct {
	id             events.ID
	chosenDirectly bool
	dependencies   events.Dependencies
	dependents     map[events.ID]struct{}
}

func newDependenciesNode(id events.ID, dependencies events.Dependencies, chosenDirectly bool) *Node {
	return &Node{
		id:             id,
		chosenDirectly: chosenDirectly,
		dependencies:   dependencies,
		dependents:     make(map[events.ID]struct{}),
	}
}

func (n *Node) GetID() events.ID {
	return n.id
}

func (n *Node) GetDependencies() events.Dependencies {
	return n.dependencies
}

func (n *Node) GetDependents() []events.ID {
	keys := make([]events.ID, 0, len(n.dependents))
	for k := range n.dependents {
		keys = append(keys, k)
	}
	return keys
}

func (n *Node) IsDependent(dependent events.ID) bool {
	_, ok := n.dependents[dependent]
	return ok
}

func (n *Node) isChosenDirectly() bool {
	return n.chosenDirectly
}

func (n *Node) markAsChosenDirectly() {
	n.chosenDirectly = true
}

func (n *Node) addDependent(dependent events.ID) {
	n.dependents[dependent] = struct{}{}
}

func (n *Node) removeDependent(dependent events.ID) {
	delete(n.dependents, dependent)
}
