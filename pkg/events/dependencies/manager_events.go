package dependencies

import (
	"errors"
	"fmt"
	"slices"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
)

// GetEvent returns the dependencies of the given event.
func (m *Manager) GetEvent(id events.ID) (*EventNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	node := m.getEventNode(id)
	if node == nil {
		return nil, ErrNodeNotFound
	}

	// Return a defensive copy to prevent callers from accessing internal state outside lock
	strategyShallowCopy := *node.dependencyStrategy
	return &EventNode{
		id:                   node.GetID(),
		explicitlySelected:   node.isExplicitlySelected(),
		dependencyStrategy:   &strategyShallowCopy,
		currentFallbackIndex: node.currentFallbackIndex,
		dependents:           slices.Clone(node.dependents),
	}, nil
}

// SelectEvent adds the given event to the management tree with default dependencies
// and marks it as explicitly selected.
// It also recursively adds all events that this event depends on (its dependencies) to the tree.
// This function has no effect if the event is already added.
func (m *Manager) SelectEvent(id events.ID) (*EventNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, err := m.buildEvent(id, nil)
	if err != nil {
		return node, err
	}

	return node, err
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

	err := m.removeEvent(id)

	return err
}

// removeEvent removes the given event from the tree.
// It also fails all dependent events.
// removeEventNode should be used instead if you already have node reference to avoid search failures.
func (m *Manager) removeEvent(id events.ID) error {
	node := m.getEventNode(id)
	if node == nil {
		return ErrNodeNotFound
	}
	return m.removeEventNode(node)
}

// removeEventNode removes the given event node from the tree.
// It also fails all dependent events.
// This is the function to call with a node that might not be already registered in the tree.
// In general, it should be used if you already have node reference to avoid search failures.
func (m *Manager) removeEventNode(eventNode *EventNode) error {
	eventName := events.Core.GetDefinitionByID(eventNode.GetID()).GetName()
	logger.Debugw("Removing event from tree", "event", eventName)

	m.removeEventNodeFromDependencies(eventNode)
	m.removeNode(eventNode)
	m.failEventDependents(eventNode)

	return nil
}

// buildEvent adds a new node for the given event if it does not exist in the tree.
// It is created with default dependencies.
// All dependencies nodes will also be created recursively with it.
// If the event exists in the tree, it will only update its dependents or its explicitlySelected
// value if it is built without dependents.
func (m *Manager) buildEvent(id events.ID, dependentEvents []events.ID) (*EventNode, error) {
	// Resolve event name once for this function (only when needed for error logging)
	eventName := events.Core.GetDefinitionByID(id).GetName()

	// Check if already processing this event (prevents loops)
	if _, processing := m.processingEvents[id]; processing {
		return nil, fmt.Errorf("event %s is currently being processed", eventName)
	}

	if _, failed := m.failedEvents[id]; failed {
		return nil, fmt.Errorf("event %s has previously failed", eventName)
	}

	// Mark as processing - this is a safeguard against recursive calls so it is not important for it to be thread-safe with the check above.
	m.processingEvents[id] = struct{}{}
	defer delete(m.processingEvents, id) // Always cleanup

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
		err = m.handleEventAddError(node, err)
		if err != nil {
			m.failedEvents[id] = struct{}{}
			logger.Debugw("Event failed to build", "event", eventName, "error", err)
			return nil, err
		}
	}
	err = m.addNode(node)
	if err != nil {
		err = m.handleEventAddError(node, err)
		if err != nil {
			m.failedEvents[id] = struct{}{}
			logger.Debugw("Event failed to add", "event", eventName, "error", err)
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

	// Build tailcall dependencies
	for _, tailCall := range eventNode.GetDependencies().GetTailCalls() {
		err := m.buildTailCall(tailCall, eventNode.GetID())
		if err != nil {
			if tailCall.IsRequired() {
				return nil, err
			}
			eventName := events.Core.GetDefinitionByID(eventNode.GetID()).GetName()
			logger.Debugw(
				"Non-required tailcall dependency adding failed for event",
				"event", eventName,
				"tailcall", GetTCKey(tailCall), "error", err,
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

// removeEventNodeFromTree removes the node from the tree.
func (m *Manager) removeEventNodeFromTree(eventNode *EventNode) {
	delete(m.events, eventNode.GetID())
}

// cleanUnreferencedEventNode removes the node from the tree if it's not required anymore.
// It also removes all of its dependencies if they are not required anymore without it.
// Returns whether it was removed or not.
func (m *Manager) cleanUnreferencedEventNode(eventNode *EventNode) bool {
	if eventNode.HasDependents() || eventNode.isExplicitlySelected() {
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
		// removeDependent returns true if the node now has no dependents
		if probe.removeDependent(eventNode.GetID()) {
			m.removeNode(probe)
		}
	}

	dependencyTailCalls := eventNode.GetDependencies().GetTailCalls()
	for _, dependencyTailCall := range dependencyTailCalls {
		tailCall := m.getTailCall(GetTCKey(dependencyTailCall))
		if tailCall == nil {
			continue
		}
		// removeDependent returns true if the node now has no dependents
		if tailCall.removeDependent(eventNode.GetID()) {
			m.removeNode(tailCall)
		}
	}

	for _, dependencyEvent := range eventNode.GetDependencies().GetIDs() {
		dependencyNode := m.getEventNode(dependencyEvent)
		if dependencyNode == nil {
			continue
		}
		if dependencyNode.removeDependent(eventNode.GetID()) {
			m.cleanUnreferencedEventNode(dependencyNode)
		}
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

// FailEvent is similar to RemoveEvent, except for the fact that instead of
// removing the current event immediately, it will try to use its fallback dependencies first.
// The old events dependencies of it will be removed in any case.
// The event will be removed if it has no fallback though, and with it the events
// that depend on it will fail as well.
// The return value specifies if the event was removed or not from the tree and any error that occurred.
func (m *Manager) FailEvent(id events.ID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed, err := m.failEvent(id)

	return removed, err
}

// failEvent attempts to switch the given event dependencies to its next available fallback ones.
// It removes the event's current dependencies and tries each fallback in order.
// If a fallback is successfully applied (i.e., buildEventNode succeeds), the function returns (false, nil),
// indicating the event was not removed but switched to a fallback.
// If no fallbacks are available or all fail, the event is removed and the function returns (true, error),
// where the error is from the removal or nil if successful.
func (m *Manager) failEvent(eventID events.ID) (bool, error) {
	// Check if already processing this event (prevents loops)
	if _, processing := m.processingEvents[eventID]; processing {
		return false, fmt.Errorf("event %v is currently being processed", eventID)
	}

	node := m.getEventNode(eventID)
	if node == nil {
		return false, ErrNodeNotFound
	}

	// Mark as processing
	m.processingEvents[eventID] = struct{}{}
	defer delete(m.processingEvents, eventID) // Always cleanup

	return m.failEventNode(node)
}

func (m *Manager) failEventNode(node *EventNode) (bool, error) {
	eventName := events.Core.GetDefinitionByID(node.GetID()).GetName()
	logger.Debugw("Failing event", "event", eventName)
	// Try fallbacks in a loop until one succeeds or we run out of fallbacks
	for node.hasMoreFallbacks() {
		m.removeEventNodeFromDependencies(node)
		if !node.fallback() {
			break
		}

		_, err := m.buildEventNode(node)
		if err == nil {
			logger.Debugw("Successfully switched to fallback", "event", eventName, "fallback_index", node.currentFallbackIndex)
			return false, nil
		}
		logger.Debugw("Failed to switch to fallback", "event", eventName, "fallback number", node.currentFallbackIndex, "error", err)
	}

	logger.Debugw("All fallbacks failed, removing event", "event", eventName)
	m.failedEvents[node.GetID()] = struct{}{}
	return true, m.removeEventNode(node)
}

// handleEventAddError handles the error of adding a node to the tree.
// As errors in adding a node to the tree are caused either by dependencies failure or by add-watchers actions,
// it will determine the handling strategy based on the error type.
func (m *Manager) handleEventAddError(node *EventNode, err error) error {
	var cancelErr *ErrNodeAddCancelled

	if errors.As(err, &cancelErr) {
		// Cancellation: immediate removal, no fallbacks
		// No need to fail event dependents, as they will fail using event add failure error handling
		eventName := events.Core.GetDefinitionByID(node.GetID()).GetName()
		logger.Debugw("Event add cancelled", "event", eventName)
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
