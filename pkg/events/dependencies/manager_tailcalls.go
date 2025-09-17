package dependencies

import (
	"fmt"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
)

// GetTailCall returns the given tailcall node managed by the Manager
func (m *Manager) GetTailCall(key string) (*TailCallNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tailCallNode := m.getTailCall(key)
	if tailCallNode == nil {
		return nil, ErrNodeNotFound
	}
	return tailCallNode, nil
}

func (m *Manager) getTailCall(key string) *TailCallNode {
	return m.tailCalls[key]
}

// buildTailCall adds the tailcall dependent to the tailcall node.
// It also creates the tailcall node if it does not exist in the tree.
func (m *Manager) buildTailCall(tailCall events.TailCall, dependent events.ID) error {
	if _, failed := m.failedTailCalls[GetTCKey(tailCall)]; failed {
		return fmt.Errorf("tailcall %v previously failed to add", GetTCKey(tailCall))
	}
	tailCallNode, ok := m.tailCalls[GetTCKey(tailCall)]
	if !ok {
		tailCallNode = NewTailCallNode(tailCall, []events.ID{dependent})
		err := m.addNode(tailCallNode)
		if err != nil {
			m.failedTailCalls[GetTCKey(tailCall)] = struct{}{}
			return err
		}
	} else {
		// Merge indexes from the new tailcall into the existing node
		// This handles the case where multiple events use the same map+program but different indexes
		indexesMerged := tailCallNode.mergeIndexes(tailCall)
		tailCallNode.addDependent(dependent)

		// If indexes were merged and the node was already in the tree, trigger state change
		// so that subscribers (like BPF initialization) can re-process the updated tailcall
		if indexesMerged {
			logger.Debugw("Merged tailcall indexes",
				"map", tailCall.GetMapName(),
				"program", tailCall.GetProgName(),
				"indexes", tailCallNode.GetTailCall().GetIndexes())
		}
	}
	return nil
}

func (m *Manager) addTailCallNodeToTree(tailCallNode *TailCallNode) {
	m.tailCalls[GetTCKey(tailCallNode.GetTailCall())] = tailCallNode
}

// removeTailCallNodeFromTree removes the node from the tree.
func (m *Manager) removeTailCallNodeFromTree(tailCallNode *TailCallNode) {
	delete(m.tailCalls, GetTCKey(tailCallNode.GetTailCall()))
}

// FailTailCall marks a tailcall as failed and fails all events that depend on it.
func (m *Manager) FailTailCall(tailCall events.TailCall) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Mark tailcall as failed
	m.failedTailCalls[GetTCKey(tailCall)] = struct{}{}

	m.removeTailCall(tailCall)

	return nil
}

// removeTailCall removes the tailcall from the tree and fails all dependent events.
func (m *Manager) removeTailCall(tailCall events.TailCall) {
	tailCallNode := m.getTailCall(GetTCKey(tailCall))
	if tailCallNode == nil {
		return
	}

	// Get all events that depend on this tailcall directly from the tailcall node
	dependentEvents := tailCallNode.GetDependents()

	// Remove the tailcall node from the tree
	m.removeNode(tailCallNode)

	// Fail all dependent events
	for _, eventID := range dependentEvents {
		// Check if the event is still in the tree and not being processed
		if eventNode := m.getEventNode(eventID); eventNode != nil {
			if _, processing := m.processingEvents[eventID]; !processing {
				isRequired := true
				for _, eventTC := range eventNode.GetDependencies().GetTailCalls() {
					if GetTCKey(eventTC) == GetTCKey(tailCall) {
						isRequired = eventTC.IsRequired()
					}
				}
				if !isRequired {
					// We don't need to fail dependent events that don't have this tailcall as a required dependency
					continue
				}
				_, err := m.failEvent(eventID)
				if err != nil {
					eventName := events.Core.GetDefinitionByID(eventID).GetName()
					logger.Warnw("failed to fail dependent event", "event", eventName, "error", err)
				}
			}
		}
	}
}
