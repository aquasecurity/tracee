package dependencies

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
)

type NodeType string

const (
	EventNodeType    NodeType = "event"
	ProbeNodeType    NodeType = "probe"
	TailCallNodeType NodeType = "tailcall"
	AllNodeTypes     NodeType = "all"
	IllegalNodeType  NodeType = "illegal"
)

// Manager is a management tree for the current dependencies of events.
// As events can depend on multiple things (e.g events, probes), it manages their connections in the form of a tree.
// The tree supports watcher functions for adding and removing nodes.
// The watchers should be used as the way to handle changes in events, probes or any other node type in Tracee.
type Manager struct {
	mu                 sync.RWMutex
	events             map[events.ID]*EventNode
	probes             map[probes.Handle]*ProbeNode
	tailCalls          map[string]*TailCallNode // See .GetKey() method for the key format
	onAdd              map[NodeType][]func(node interface{}) []Action
	onRemove           map[NodeType][]func(node interface{}) []Action
	dependenciesGetter func(events.ID) events.DependencyStrategy
	// Track failed probes and events to prevent issues such as incorrect fallback handling,
	// duplicate processing, or inconsistent state when dependencies are shared between events.
	failedProbes    map[probes.Handle]struct{}
	failedEvents    map[events.ID]struct{}
	failedTailCalls map[string]struct{}

	processingEvents map[events.ID]struct{} // Track events currently being processed - safeguard against recursive calls
}

func NewDependenciesManager(dependenciesGetter func(events.ID) events.DependencyStrategy) *Manager {
	return &Manager{
		mu:                 sync.RWMutex{},
		events:             make(map[events.ID]*EventNode),
		probes:             make(map[probes.Handle]*ProbeNode),
		tailCalls:          make(map[string]*TailCallNode),
		onAdd:              make(map[NodeType][]func(node interface{}) []Action),
		onRemove:           make(map[NodeType][]func(node interface{}) []Action),
		dependenciesGetter: dependenciesGetter,
		failedProbes:       make(map[probes.Handle]struct{}),
		failedEvents:       make(map[events.ID]struct{}),
		failedTailCalls:    make(map[string]struct{}),
		processingEvents:   make(map[events.ID]struct{}), // Initialize processing state
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

// addNode adds a node generically to the tree and triggers the on-add watchers.
// It returns an error if the node is not of a valid type, or if the on-add watchers return an error.
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
		m.addProbeNodeToTree(node.(*ProbeNode))
	case TailCallNodeType:
		m.addTailCallNodeToTree(node.(*TailCallNode))
	}
	return nil
}

// removeNode removes a node generically from the tree and triggers the on-remove watchers.
// It returns an error if the node is not of a valid type, or if the on-remove watchers return an error.
func (m *Manager) removeNode(node interface{}) {
	nodeType, err := getNodeType(node)
	if err != nil {
		logger.Debugw("failed to get node type", "error", err)
		return
	}

	m.triggerOnRemove(node)

	switch nodeType {
	case EventNodeType:
		m.removeEventNodeFromTree(node.(*EventNode))
	case ProbeNodeType:
		m.removeProbeNodeFromTree(node.(*ProbeNode))
	case TailCallNodeType:
		m.removeTailCallNodeFromTree(node.(*TailCallNode))
	}
}

// triggerOnAdd triggers all on-add watchers and handle their returned actions.
// As the tree supports cancelling or failing node add actions, it will return an error if the node add was cancelled or failed.
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
	case *TailCallNode:
		return TailCallNodeType, nil
	}
	return IllegalNodeType, fmt.Errorf("unknown node type: %s", reflect.TypeOf(node))
}

func (m *Manager) GetEvents() []events.ID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Collect(maps.Keys(m.events))
}

func (m *Manager) GetProbes() []probes.Handle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Collect(maps.Keys(m.probes))
}

func (m *Manager) GetTailCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Collect(maps.Keys(m.tailCalls))
}
