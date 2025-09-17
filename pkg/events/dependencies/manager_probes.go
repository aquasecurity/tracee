package dependencies

import (
	"fmt"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
)

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

func (m *Manager) getProbe(handle probes.Handle) *ProbeNode {
	return m.probes[handle]
}

// buildProbe adds the probe dependent to the probe node.
// It also creates the probe node if it does not exist in the tree.
func (m *Manager) buildProbe(handle probes.Handle, dependent events.ID) error {
	if _, failed := m.failedProbes[handle]; failed {
		return fmt.Errorf("probe %v previously failed to add", handle)
	}
	probeNode, ok := m.probes[handle]
	if !ok {
		probeNode = NewProbeNode(handle, []events.ID{dependent})
		err := m.addNode(probeNode)
		if err != nil {
			m.failedProbes[handle] = struct{}{}
			return err
		}
	} else {
		probeNode.addDependent(dependent)
	}
	return nil
}

func (m *Manager) addProbeNodeToTree(probeNode *ProbeNode) {
	m.probes[probeNode.GetHandle()] = probeNode
}

// removeProbeNodeFromTree removes the node from the tree.
func (m *Manager) removeProbeNodeFromTree(handle *ProbeNode) {
	delete(m.probes, handle.GetHandle())
}

// FailProbe marks a probe as failed and fails all events that depend on it.
func (m *Manager) FailProbe(handle probes.Handle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Mark probe as failed
	m.failedProbes[handle] = struct{}{}

	m.removeProbe(handle)

	return nil
}

// removeProbe removes the probe from the tree and fails all dependent events.
func (m *Manager) removeProbe(handle probes.Handle) {
	probeNode := m.getProbe(handle)
	if probeNode == nil {
		return
	}

	// Get all events that depend on this probe directly from the probe node
	dependentEvents := probeNode.GetDependents()

	// Remove the probe node from the tree
	m.removeNode(probeNode)

	// Fail all dependent events
	for _, eventID := range dependentEvents {
		// Check if the event is still in the tree and not being processed
		if eventNode := m.getEventNode(eventID); eventNode != nil {
			if _, processing := m.processingEvents[eventID]; !processing {
				isRequired := true
				for _, probe := range eventNode.GetDependencies().GetProbes() {
					if probe.GetHandle() == handle {
						isRequired = probe.IsRequired()
					}
				}
				if !isRequired {
					// We don't need to fail dependent events that don't have this probe as a required dependency
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
