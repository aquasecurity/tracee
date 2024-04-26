package dependencies

import (
	"github.com/aquasecurity/tracee/pkg/events"
)

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
func (m *Manager) SubscribeAdd(onAdd func(*EventNode)) {
	m.onAdd = append(m.onAdd, onAdd)
}

// SubscribeRemove adds a watcher function called upon the removal of an event from the tree.
func (m *Manager) SubscribeRemove(onRemove func(*EventNode)) {
	m.onRemove = append(m.onRemove, onRemove)
}

// GetEvent returns the dependencies of the given event.
func (m *Manager) GetEvent(id events.ID) (*EventNode, bool) {
	node := m.getNode(id)
	if node == nil {
		return nil, false
	}
	return node, true
}

// SelectEvent adds the given event to the management tree with default dependencies
// and marks it as explicitly selected.
// It also recursively adds all events that this event depends on (its dependencies) to the tree.
// This function has no effect if the event is already added.
func (m *Manager) SelectEvent(id events.ID) *EventNode {
	return m.buildEvent(id, nil)
}

// UnselectEvent marks the event as not explicitly selected.
// If the event is not a dependency of another event, it will be removed
// from the tree, and its dependencies will be cleaned if they are not referenced or explicitly selected.
// Returns whether it was removed.
func (m *Manager) UnselectEvent(id events.ID) bool {
	node := m.getNode(id)
	if node == nil {
		return false
	}
	node.unmarkAsExplicitlySelected()
	return m.cleanUnreferencedNode(node)
}

// RemoveEvent removes the given event from the management tree.
// It removes its reference from its dependencies. If these events
// were added to the tree only as dependencies, they will be removed as well if
// they are not referenced by any other event anymore and not explicitly selected.
// It also removes all the events that depend on the given event (as their dependencies are
// no longer valid).
// It returns if managed to remove the event, as it might not be present in the tree.
func (m *Manager) RemoveEvent(id events.ID) bool {
	node := m.getNode(id)
	if node == nil {
		return false
	}
	m.removeNode(node)
	m.removeNodeFromDependencies(node)
	m.removeDependants(node)
	return true
}

func (m *Manager) getNode(id events.ID) *EventNode {
	return m.nodes[id]
}

// Nodes are added either because they are explicitly selected or because they are a dependency
// of another event.
// We want the watchers to have access to the cause of the node addition, so we add the dependants
// before we call the watchers.
func (m *Manager) addNode(node *EventNode, dependantEvents []events.ID) {
	m.nodes[node.GetID()] = node
	for _, dependant := range dependantEvents {
		node.addDependant(dependant)
	}
	for _, onAdd := range m.onAdd {
		onAdd(node)
	}
}

// buildEvent adds a new node for the given event if it does not exist in the tree.
// It is created with default dependencies.
// All dependency events will also be created recursively with it.
// If the event exists in the tree, it will only update its explicitlySelected value if
// it is built without dependants.
func (m *Manager) buildEvent(id events.ID, dependantEvents []events.ID) *EventNode {
	explicitlySelected := len(dependantEvents) == 0
	node := m.getNode(id)
	if node != nil {
		if explicitlySelected {
			node.markAsExplicitlySelected()
		}
		return node
	}
	// Create node for the given ID and dependencies
	dependencies := m.dependenciesGetter(id)
	node = newDependenciesNode(id, dependencies, explicitlySelected)
	m.addNode(node, dependantEvents)

	m.buildNode(node)
	return node
}

// buildNode adds the dependencies of the current node to the tree and creates
// all needed references.
func (m *Manager) buildNode(node *EventNode) *EventNode {
	// Get the dependency event IDs
	dependenciesIDs := node.GetDependencies().GetIDs()

	// Create nodes for all dependency events and their dependencies recursively
	for _, dependencyID := range dependenciesIDs {
		dependencyNode := m.getNode(dependencyID)
		if dependencyNode == nil {
			m.buildEvent(
				dependencyID,
				[]events.ID{node.GetID()},
			)
		}
	}
	return node
}

// removeNode removes the node from the tree.
func (m *Manager) removeNode(node *EventNode) bool {
	delete(m.nodes, node.GetID())
	for _, onRemove := range m.onRemove {
		onRemove(node)
	}
	return true
}

// cleanUnreferencedNode removes the node from the tree if it's not required anymore.
// It also removes all of its dependencies if they are not required anymore without it.
// Returns whether it was removed or not.
func (m *Manager) cleanUnreferencedNode(node *EventNode) bool {
	if len(node.GetDependants()) > 0 || node.isExplicitlySelected() {
		return false
	}
	m.removeNode(node)
	m.removeNodeFromDependencies(node)
	return true
}

// removeNodeFromDependencies removes the reference to the given node from its dependencies.
// It removes the dependencies from the tree if they are not chosen directly
// and no longer have any dependant event.
func (m *Manager) removeNodeFromDependencies(node *EventNode) {
	for _, dependencyEvent := range node.GetDependencies().GetIDs() {
		dependencyNode := m.getNode(dependencyEvent)
		if dependencyNode == nil {
			continue
		}
		dependencyNode.removeDependant(node.GetID())
		if m.cleanUnreferencedNode(dependencyNode) {
			for _, onRemove := range m.onRemove {
				onRemove(dependencyNode)
			}
		}
	}
}

// removeDependants removes all dependant events from the tree
func (m *Manager) removeDependants(node *EventNode) {
	for _, dependantEvent := range node.GetDependants() {
		m.RemoveEvent(dependantEvent)
	}
}
