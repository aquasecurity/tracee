package dependencies

import "github.com/aquasecurity/tracee/pkg/events"

// Manager is a management tree for current dependencies of events
// As events can depend on one another, it manages their connection to one
// another in the form of a tree.
// The tree support watcher functions for indirect add and remove of nodes.
type Manager struct {
	nodes              map[events.ID]*Node
	onIndirectAdd      []func(events.ID)
	onIndirectRemove   []func(events.ID)
	dependenciesGetter func(events.ID) events.Dependencies
}

func NewDependenciesManager(dependenciesGetter func(events.ID) events.Dependencies) *Manager {
	return &Manager{
		nodes:              make(map[events.ID]*Node),
		dependenciesGetter: dependenciesGetter,
	}
}

// SubscribeIndirectAdd add a watcher function called upon addition of an event which is a dependency
// of another event
// This is done so because direct add can be handled by the adding function.
func (t *Manager) SubscribeIndirectAdd(onAdd func(events.ID)) {
	t.onIndirectAdd = append(t.onIndirectAdd, onAdd)
}

// SubscribeIndirectRemove add a watcher function called upon remove of an event which is a dependency
// of another event.
// This is done so because direct remove can be handled by the removing function.
func (t *Manager) SubscribeIndirectRemove(onRemove func(events.ID)) {
	t.onIndirectRemove = append(t.onIndirectRemove, onRemove)
}

// GetEvent return the dependencies of given event
func (t *Manager) GetEvent(id events.ID) (events.Dependencies, bool) {
	node := t.getNode(id)
	if node == nil {
		return events.Dependencies{}, false
	}
	return node.GetDependencies(), true
}

// GetDependantEvents return all the events that depend on current event
func (t *Manager) GetDependantEvents(id events.ID) ([]events.ID, bool) {
	node := t.getNode(id)
	if node == nil {
		return nil, false
	}
	return node.GetDependents(), true
}

// AddEvent add given event to the management tree with default dependencies.
// It will also add to the tree all the dependency events of the given event.
// This function has no effect if the event is already added.
func (t *Manager) AddEvent(id events.ID) events.Dependencies {
	return t.buildEvent(id, nil).GetDependencies()
}

// RemoveEvent removes the given event from the management tree.
// It will remove its reference from events that it depends on. If these events
// were added to the tree only as dependencies, it will remove them as well if
// they are not referenced by any other event anymore.
// It will also remove all events that depend on given event.
func (t *Manager) RemoveEvent(id events.ID) {
	node := t.getNode(id)
	t.removeNodeFromDependencies(node)
	t.removeNode(id)
	t.removeDependants(node)
}

func (t *Manager) getNode(id events.ID) *Node {
	return t.nodes[id]
}

func (t *Manager) removeNode(id events.ID) {
	delete(t.nodes, id)
}

// buildEvent add a new node for the given event if it does not exist in the tree.
// It will be created with default dependencies.
// All dependencies events will be also created recursively with it.
// If the event exist in the tree, will only update its chosenDirectly value if
// it's true.
func (t *Manager) buildEvent(id events.ID, dependantEvents []events.ID) *Node {
	chosenDirectly := len(dependantEvents) == 0
	node := t.getNode(id)
	if node != nil {
		if chosenDirectly {
			node.markAsChosenDirectly()
		}
		return node
	}
	// Create node for the given ID and dependencies
	dependencies := t.dependenciesGetter(id)
	node = newDependenciesNode(id, dependencies, chosenDirectly)
	t.nodes[id] = node

	for _, dependant := range dependantEvents {
		node.addDependent(dependant)
	}

	if !node.isChosenDirectly() {
		for _, onAdd := range t.onIndirectAdd {
			onAdd(node.GetID())
		}
	}

	t.buildNode(node)
	return node
}

// buildNode add all dependencies nodes of current node to the tree and create
// all needed references.
func (t *Manager) buildNode(node *Node) *Node {
	// Get the dependencies events IDs
	dependenciesIDs := node.GetDependencies().GetIDs()

	// Create nodes for all dependencies events and their dependencies recursively
	for _, dependencyID := range dependenciesIDs {
		dependencyNode := t.getNode(dependencyID)
		if dependencyNode == nil {
			t.buildEvent(
				dependencyID,
				[]events.ID{node.GetID()},
			)
		}
	}
	return node
}

// removeNodeFromDependencies remove the reference to given node from its dependencies.
// It will remove the dependencies from the tree if they are not chosen directly
// and no longer have any dependant event.
func (t *Manager) removeNodeFromDependencies(node *Node) {
	for _, dependencyEvent := range node.GetDependencies().GetIDs() {
		dependencyNode := t.getNode(dependencyEvent)
		if dependencyNode == nil {
			continue
		}
		dependencyNode.removeDependent(node.GetID())
		// We want to remove nodes that are added as dependencies by the current node if they
		// are note dependencies of other nodes
		if len(dependencyNode.GetDependents()) == 0 && !dependencyNode.isChosenDirectly() {
			t.RemoveEvent(dependencyEvent)
			for _, onRemove := range t.onIndirectRemove {
				onRemove(dependencyEvent)
			}
		}
	}
}

func (t *Manager) removeDependants(node *Node) {
	for _, dependantEvent := range node.GetDependents() {
		t.RemoveEvent(dependantEvent)
		for _, onRemove := range t.onIndirectRemove {
			onRemove(dependantEvent)
		}
	}
}
