package dependencies

import "github.com/aquasecurity/tracee/pkg/events"

// Manager is a management tree for the current dependencies of events.
// As events can depend on one another, it manages their connection in the form of a tree.
// The tree supports watcher functions for adding and removing nodes.
// The manager is *not* thread-safe.
type Manager struct {
	nodes              map[events.ID]*EventNode
	onAdd              []func(*EventNode)
	onRemove           []func(*EventNode)
	dependenciesGetter func(events.ID) events.Dependencies
}

func NewDependenciesManager(dependenciesGetter func(events.ID) events.Dependencies) *Manager {
	return &Manager{
		nodes:              make(map[events.ID]*EventNode),
		dependenciesGetter: dependenciesGetter,
	}
}

// SubscribeAdd adds a watcher function called upon the addition of an event to the tree.
func (t *Manager) SubscribeAdd(onAdd func(*EventNode)) {
	t.onAdd = append(t.onAdd, onAdd)
}

// SubscribeRemove adds a watcher function called upon the removal of an event from the tree.
func (t *Manager) SubscribeRemove(onRemove func(*EventNode)) {
	t.onRemove = append(t.onRemove, onRemove)
}

// GetEvent returns the dependencies of the given event.
func (t *Manager) GetEvent(id events.ID) (*EventNode, bool) {
	node := t.getNode(id)
	if node == nil {
		return nil, false
	}
	return node, true
}

// SelectEvent adds the given event to the management tree with default dependencies
// and marks it as explicitly selected.
// It also adds all the dependency events of the given event to the tree.
// This function has no effect if the event is already added.
func (t *Manager) SelectEvent(id events.ID) *EventNode {
	return t.buildEvent(id, nil)
}

// UnselectEvent marks the event as not explicitly selected.
// If the event is not a dependency of another event, it will be removed
// from the tree, and its dependencies will be cleaned if they are not referenced or explicitly selected.
// Returns whether it was removed.
func (t *Manager) UnselectEvent(id events.ID) bool {
	node := t.getNode(id)
	node.unmarkAsExplicitlySelected()
	return t.cleanUnreferencedNode(node)
}

// RemoveEvent removes the given event from the management tree.
// It removes its reference from events that depend on it. If these events
// were added to the tree only as dependencies, they will be removed as well if
// they are not referenced by any other event anymore and not explicitly selected.
// It also removes all events that depend on the given event.
func (t *Manager) RemoveEvent(id events.ID) {
	node := t.getNode(id)
	t.removeNode(node.GetID())
	t.removeNodeFromDependencies(node)
	t.removeDependants(node)
}

func (t *Manager) getNode(id events.ID) *EventNode {
	return t.nodes[id]
}

// Nodes are added either because they are explicitly selected or because they are a dependency
// of another event.
// We want the watchers to have access to the cause of the node addition, so we add the dependants
// before we call the watchers.
func (t *Manager) addNode(node *EventNode, dependantEvents []events.ID) {
	t.nodes[node.GetID()] = node
	for _, dependant := range dependantEvents {
		node.addDependant(dependant)
	}
	for _, onAdd := range t.onAdd {
		onAdd(node)
	}
}

// buildEvent adds a new node for the given event if it does not exist in the tree.
// It is created with default dependencies.
// All dependency events will also be created recursively with it.
// If the event exists in the tree, it will only update its explicitlySelected value if
// it is built without dependants.
func (t *Manager) buildEvent(id events.ID, dependantEvents []events.ID) *EventNode {
	explicitlySelected := len(dependantEvents) == 0
	node := t.getNode(id)
	if node != nil {
		if explicitlySelected {
			node.markAsExplicitlySelected()
		}
		return node
	}
	// Create node for the given ID and dependencies
	dependencies := t.dependenciesGetter(id)
	node = newDependenciesNode(id, dependencies, explicitlySelected)
	t.addNode(node, dependantEvents)

	t.buildNode(node)
	return node
}

// buildNode adds all dependency nodes of the current node to the tree and creates
// all needed references.
func (t *Manager) buildNode(node *EventNode) *EventNode {
	// Get the dependency event IDs
	dependenciesIDs := node.GetDependencies().GetIDs()

	// Create nodes for all dependency events and their dependencies recursively
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

func (t *Manager) removeNode(id events.ID) {
	node := t.getNode(id)
	delete(t.nodes, id)
	for _, onRemove := range t.onRemove {
		onRemove(node)
	}
}

// cleanUnreferencedNode removes the node from the tree if it's not required anymore.
// It also removes all of its dependencies if they are not required anymore without it.
// Returns whether it was removed or not.
func (t *Manager) cleanUnreferencedNode(node *EventNode) bool {
	if len(node.GetDependants()) > 0 || node.isExplicitlySelected() {
		return false
	}
	t.removeNode(node.GetID())
	t.removeNodeFromDependencies(node)
	return true
}

// removeNodeFromDependencies removes the reference to the given node from its dependencies.
// It removes the dependencies from the tree if they are not chosen directly
// and no longer have any dependant event.
func (t *Manager) removeNodeFromDependencies(node *EventNode) {
	for _, dependencyEvent := range node.GetDependencies().GetIDs() {
		dependencyNode := t.getNode(dependencyEvent)
		if dependencyNode == nil {
			continue
		}
		dependencyNode.removeDependant(node.GetID())
		if t.cleanUnreferencedNode(dependencyNode) {
			for _, onRemove := range t.onRemove {
				onRemove(dependencyNode)
			}
		}
	}
}

// removeDependants removes all dependant events from the tree
func (t *Manager) removeDependants(node *EventNode) {
	for _, dependantEvent := range node.GetDependants() {
		t.RemoveEvent(dependantEvent)
	}
}
