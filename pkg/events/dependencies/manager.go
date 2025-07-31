package dependencies

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type NodeType string

const (
	EventNodeType   NodeType = "event"
	ProbeNodeType   NodeType = "probe"
	AllNodeTypes    NodeType = "all"
	IllegalNodeType NodeType = "illegal"
)

// Manager is a management tree for the current dependencies of events.
// As events can depend on multiple things (e.g events, probes), it manages their connections in the form of a tree.
// The tree supports watcher functions for adding and removing nodes.
// The watchers should be used as the way to handle changes in events, probes or any other node type in Tracee.
type Manager struct {
	mu                 sync.RWMutex
	events             map[events.ID]*EventNode
	probes             map[probes.Handle]*ProbeNode
	onAdd              map[NodeType][]func(node interface{}) []Action
	onRemove           map[NodeType][]func(node interface{}) []Action
	dependenciesGetter func(events.ID) events.Dependencies
}

func NewDependenciesManager(dependenciesGetter func(events.ID) events.Dependencies) *Manager {
	return &Manager{
		mu:                 sync.RWMutex{},
		events:             make(map[events.ID]*EventNode),
		probes:             make(map[probes.Handle]*ProbeNode),
		onAdd:              make(map[NodeType][]func(node interface{}) []Action),
		onRemove:           make(map[NodeType][]func(node interface{}) []Action),
		dependenciesGetter: dependenciesGetter,
	}
}

// SubscribeAdd adds a watcher function called upon the addition of an event to the tree.
// Add watcher are called in the order of their subscription.
func (m *Manager) SubscribeAdd(subscribeType NodeType, onAdd func(node interface{}) []Action) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.onAdd[subscribeType] = append(m.onAdd[subscribeType], onAdd)
}

// SubscribeRemove adds a watcher function called upon the removal of an event from the tree.
// Remove watchers are called in reverse order of their subscription.
func (m *Manager) SubscribeRemove(subscribeType NodeType, onRemove func(node interface{}) []Action) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.onRemove[subscribeType] = append([]func(node interface{}) []Action{onRemove}, m.onRemove[subscribeType]...)
}

// GetEvent returns the dependencies of the given event.
func (m *Manager) GetEvent(id events.ID) (*EventNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	node := m.getEventNode(id)
	if node == nil {
		return nil, ErrNodeNotFound
	}
	return node, nil
}

// GetProbe returns the given probe node managed by the Manager
func (m *Manager) GetProbe(handle probes.Handle) (*ProbeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	probeNode := m.getProbe(handle)
	if probeNode == nil {
		return nil, ErrNodeNotFound
	}
	return probeNode, nil
}

// SelectEvent adds the given event to the management tree with default dependencies
// and marks it as explicitly selected.
// It also recursively adds all events that this event depends on (its dependencies) to the tree.
// This function has no effect if the event is already added.
func (m *Manager) SelectEvent(id events.ID) (*EventNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.buildEvent(id, nil)
}

// UnselectEvent marks the event as not explicitly selected.
// If the event is not a dependency of another event, it will be removed
// from the tree, and its dependencies will be cleaned if they are not referenced or explicitly selected.
// Returns whether it was removed.
func (m *Manager) UnselectEvent(id events.ID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	node := m.getEventNode(id)
	if node == nil {
		return false
	}
	node.unmarkAsExplicitlySelected()
	removed := m.cleanUnreferencedEventNode(node)
	return removed
}

// RemoveEvent removes the given event from the management tree.
// It removes its reference from its dependencies. If these events
// were added to the tree only as dependencies, they will be removed as well if
// they are not referenced by any other event anymore and not explicitly selected.
// It also removes all the events that depend on the given event (as their dependencies are
// no longer valid).
// It returns if managed to remove the event, as it might not be present in the tree.
func (m *Manager) RemoveEvent(id events.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.removeEvent(id)
}

// removeEvent removes the given event from the tree.
// It also fails all dependent events.
func (m *Manager) removeEvent(id events.ID) error {
	node := m.getEventNode(id)
	if node == nil {
		return ErrNodeNotFound
	}

	m.removeEventNodeFromDependencies(node)
	m.removeNode(node)
	m.failEventDependents(node)

	return nil
}

// buildEvent adds a new node for the given event if it does not exist in the tree.
// It is created with default dependencies.
// All dependencies nodes will also be created recursively with it.
// If the event exists in the tree, it will only update its dependents or its explicitlySelected
// value if it is built without dependents.
func (m *Manager) buildEvent(id events.ID, dependentEvents []events.ID) (*EventNode, error) {
	explicitlySelected := len(dependentEvents) == 0
	node := m.getEventNode(id)
	if node != nil {
		if explicitlySelected {
			node.markAsExplicitlySelected()
		}
		for _, dependent := range dependentEvents {
			node.addDependent(dependent)
		}
		return node, nil
	}
	// Create node for the given ID and dependencies
	dependencies := m.dependenciesGetter(id)
	node = newDependenciesNode(id, dependencies, explicitlySelected)
	for _, dependent := range dependentEvents {
		node.addDependent(dependent)
	}
	_, err := m.buildEventNode(node)
	if err != nil {
		err = m.handleAddError(node, err)
		if err != nil {
			return nil, err
		}
	}
	err = m.addNode(node)
	if err != nil {
		err = m.handleAddError(node, err)
		if err != nil {
			return nil, err
		}
	}
	return node, nil
}

// buildEventNode adds the dependencies of the current node to the tree and creates
// all needed references between nodes.
func (m *Manager) buildEventNode(eventNode *EventNode) (*EventNode, error) {
	// Get the dependency event IDs
	dependenciesIDs := eventNode.GetDependencies().GetIDs()

	// Build probe dependencies
	for _, probe := range eventNode.GetDependencies().GetProbes() {
		err := m.buildProbe(probe.GetHandle(), eventNode.GetID())
		if err != nil {
			if probe.IsRequired() {
				return nil, err
			}
			eventName := events.Core.GetDefinitionByID(eventNode.GetID()).GetName()
			logger.Debugw(
				"Non-required probe dependency adding failed for event",
				"event", eventName,
				"probe", probe.GetHandle(), "error", err,
			)
			continue
		}
	}

	// Create nodes for all the events the node depends on and their dependencies recursively,
	// or update them if they already exist
	for _, dependencyID := range dependenciesIDs {
		_, err := m.buildEvent(
			dependencyID,
			[]events.ID{eventNode.GetID()},
		)
		if err != nil {
			// If a dependency was cancelled, convert to failure for this dependent event
			// This ensures dependent events use fallback mechanisms instead of being cancelled
			var cancelErr *ErrNodeAddCancelled
			if errors.As(err, &cancelErr) {
				// Convert cancellation to failure for dependent events
				failureReasons := make([]error, len(cancelErr.Reasons))
				for i, reason := range cancelErr.Reasons {
					failureReasons[i] = fmt.Errorf("dependency cancelled: %w", reason)
				}
				return nil, NewErrNodeAddFailed(failureReasons)
			}
			return nil, err
		}
	}
	return eventNode, nil
}

func (m *Manager) getEventNode(id events.ID) *EventNode {
	return m.events[id]
}

// Nodes are added either because they are explicitly selected or because they are a dependency
// of another event.
func (m *Manager) addEventNode(eventNode *EventNode) {
	m.events[eventNode.GetID()] = eventNode
}

// removeEventNode removes the node from the tree.
func (m *Manager) removeEventNode(eventNode *EventNode) {
	delete(m.events, eventNode.GetID())
}

func (m *Manager) addNode(node interface{}) error {
	nodeType, err := getNodeType(node)
	if err != nil {
		return err
	}

	err = m.triggerOnAdd(node)
	if err != nil {
		return err
	}

	switch nodeType {
	case EventNodeType:
		m.addEventNode(node.(*EventNode))
	case ProbeNodeType:
		m.addProbe(node.(*ProbeNode))
	}
	return nil
}

func (m *Manager) removeNode(node interface{}) {
	nodeType, err := getNodeType(node)
	if err != nil {
		logger.Debugw("failed to get node type", "error", err)
		return
	}

	m.triggerOnRemove(node)

	switch nodeType {
	case EventNodeType:
		m.removeEventNode(node.(*EventNode))
	case ProbeNodeType:
		m.removeProbe(node.(*ProbeNode))
	}
}

// triggerOnAdd triggers all on-add watchers and handle their returned actions.
func (m *Manager) triggerOnAdd(node interface{}) error {
	nodeType, err := getNodeType(node)
	if err != nil {
		logger.Debugw("failed to get node type", "error", err)
		return ErrNodeType
	}
	var actions []Action
	addWatchers := m.onAdd[nodeType]
	for _, onAdd := range addWatchers {
		actions = append(actions, onAdd(node)...)
	}
	addWatchers = m.onAdd[AllNodeTypes]
	for _, onAdd := range addWatchers {
		actions = append(actions, onAdd(node)...)
	}

	var cancelNodeAddErr *ErrNodeAddCancelled
	var failNodeAddErr *ErrNodeAddFailed
	shouldCancel := false
	shouldFail := false

	for _, action := range actions {
		switch typedAction := action.(type) {
		case *CancelNodeAddAction:
			shouldCancel = true
			if cancelNodeAddErr == nil {
				cancelNodeAddErr = NewErrNodeAddCancelled([]error{typedAction.Reason})
			} else {
				cancelNodeAddErr.AddReason(typedAction.Reason)
			}
		case *FailNodeAddAction:
			shouldFail = true
			if failNodeAddErr == nil {
				failNodeAddErr = NewErrNodeAddFailed([]error{typedAction.Reason})
			} else {
				failNodeAddErr.AddReason(typedAction.Reason)
			}
		}
	}

	// Cancellation takes priority over failure
	if shouldCancel {
		return cancelNodeAddErr
	}
	if shouldFail {
		return failNodeAddErr
	}
	return nil
}

// triggerOnRemove triggers all on-remove watchers
func (m *Manager) triggerOnRemove(node interface{}) {
	nodeType, err := getNodeType(node)
	if err != nil {
		logger.Debugw("failed to get node type", "error", err)
		return
	}
	removeWatchers := m.onRemove[nodeType]
	for _, onRemove := range removeWatchers {
		onRemove(node)
	}
	removeWatchers = m.onRemove[AllNodeTypes]
	for _, onRemove := range removeWatchers {
		onRemove(node)
	}
}

func getNodeType(node interface{}) (NodeType, error) {
	switch node.(type) {
	case *EventNode:
		return EventNodeType, nil
	case *ProbeNode:
		return ProbeNodeType, nil
	}
	return IllegalNodeType, fmt.Errorf("unknown node type: %s", reflect.TypeOf(node))
}

// cleanUnreferencedEventNode removes the node from the tree if it's not required anymore.
// It also removes all of its dependencies if they are not required anymore without it.
// Returns whether it was removed or not.
func (m *Manager) cleanUnreferencedEventNode(eventNode *EventNode) bool {
	if len(eventNode.GetDependents()) > 0 || eventNode.isExplicitlySelected() {
		return false
	}
	m.removeNode(eventNode)
	m.removeEventNodeFromDependencies(eventNode)
	return true
}

// removeEventNodeFromDependencies removes the reference to the given node from its dependencies.
// It removes the dependencies from the tree if they are not chosen directly
// and no longer have any dependent event.
func (m *Manager) removeEventNodeFromDependencies(eventNode *EventNode) {
	dependencyProbes := eventNode.GetDependencies().GetProbes()
	for _, dependencyProbe := range dependencyProbes {
		probe := m.getProbe(dependencyProbe.GetHandle())
		if probe == nil {
			continue
		}
		probe.removeDependent(eventNode.GetID())
		if len(probe.GetDependents()) == 0 {
			m.removeNode(probe)
		}
	}

	for _, dependencyEvent := range eventNode.GetDependencies().GetIDs() {
		dependencyNode := m.getEventNode(dependencyEvent)
		if dependencyNode == nil {
			continue
		}
		dependencyNode.removeDependent(eventNode.GetID())
		m.cleanUnreferencedEventNode(dependencyNode)
	}
}

// failEventDependents fails all dependent events from the tree
func (m *Manager) failEventDependents(eventNode *EventNode) {
	for _, dependentEvent := range eventNode.GetDependents() {
		_, err := m.failEvent(dependentEvent)
		if err != nil {
			eventName := events.Core.GetDefinitionByID(dependentEvent).GetName()
			logger.Debugw("failed to fail dependent event", "event", eventName, "error", err)
		}
	}
}

func (m *Manager) getProbe(handle probes.Handle) *ProbeNode {
	return m.probes[handle]
}

func (m *Manager) buildProbe(handle probes.Handle, dependent events.ID) error {
	probeNode, ok := m.probes[handle]
	if !ok {
		probeNode = NewProbeNode(handle, []events.ID{dependent})
		err := m.addNode(probeNode)
		if err != nil {
			return err
		}
	} else {
		probeNode.addDependent(dependent)
	}
	return nil
}

func (m *Manager) addProbe(probeNode *ProbeNode) {
	m.probes[probeNode.GetHandle()] = probeNode
}

// removeNode removes the node from the tree.
func (m *Manager) removeProbe(handle *ProbeNode) {
	delete(m.probes, handle.GetHandle())
}

// FailEvent is similar to RemoveEvent, except for the fact that instead of
// removing the current event it will try to use its fallback dependencies.
// The old events dependencies of it will be removed in any case.
// The event will be removed if it has no fallback though, and with it the events
// that depend on it.
// The return value specifies if the event was removed or not from the tree and any error that occurred.
func (m *Manager) FailEvent(id events.ID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.failEvent(id)
}

// failEvent attempts to switch the given event to its next available fallback dependencies.
// It removes the event's current dependencies and tries each fallback in order.
// If a fallback is successfully applied (i.e., buildEventNode succeeds), the function returns (false, nil),
// indicating the event was not removed but switched to a fallback.
// If no fallbacks are available or all fail, the event is removed and the function returns (true, error),
// where the error is from the removal or nil if successful.
func (m *Manager) failEvent(eventID events.ID) (bool, error) {
	node := m.getEventNode(eventID)
	if node == nil {
		return false, ErrNodeNotFound
	}

	return m.failEventNode(node)
}

func (m *Manager) failEventNode(node *EventNode) (bool, error) {
	// Try fallbacks in a loop until one succeeds or we run out
	for node.hasMoreFallbacks() {
		m.removeEventNodeFromDependencies(node)
		if !node.fallback() {
			break
		}

		_, err := m.buildEventNode(node)
		if err == nil {
			return false, nil
		}
	}
	return true, m.removeEvent(node.GetID())
}

func (m *Manager) handleAddError(node *EventNode, err error) error {
	var cancelErr *ErrNodeAddCancelled

	if errors.As(err, &cancelErr) {
		// Cancellation: immediate removal, no fallbacks
		// No need to fail event dependents, as they will fail using event add failure error handling
		m.removeEventNodeFromDependencies(node)
		m.removeNode(node)
		return err
	}
	// Failure: try fallbacks
	removed, failEventErr := m.failEventNode(node)
	if failEventErr != nil {
		logger.Errorw("Failed to fail", "error", failEventErr)
		m.removeEventNodeFromDependencies(node)
		return err
	}
	if removed {
		// All fallbacks exhausted, event was removed
		return err
	}
	// Fallback succeeded, no error to return
	return nil
}
