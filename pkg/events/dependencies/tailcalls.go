package dependencies

import (
	"slices"

	"github.com/aquasecurity/tracee/pkg/events"
)

// TailCallNode represents a tailcall entry in the dependency tree.
// A tailcall is identified by its map name, program name, and index.
type TailCallNode struct {
	tailCall   events.TailCall
	dependents []events.ID // Events that depend on this tailcall
}

func NewTailCallNode(tailCall events.TailCall, dependents []events.ID) *TailCallNode {
	return &TailCallNode{
		tailCall:   tailCall,
		dependents: dependents,
	}
}

func (tn *TailCallNode) GetTailCall() events.TailCall {
	return tn.tailCall
}

// mergeIndexes merges new indexes into the existing tailcall.
// This is needed when multiple events use the same map+program combination but with different indexes.
// Returns true if indexes were actually merged (changed), false if no change occurred.
func (tn *TailCallNode) mergeIndexes(newTailCall events.TailCall) bool {
	oldIndexCount := len(tn.tailCall.GetIndexes())
	// Use the helper function from events package to create a new TailCall with merged indexes
	tn.tailCall = events.NewTailCallWithMergedIndexes(tn.tailCall, newTailCall.GetIndexes())
	newIndexCount := len(tn.tailCall.GetIndexes())
	// Return true if the number of indexes changed (indicating a merge occurred)
	return newIndexCount != oldIndexCount
}

func (tn *TailCallNode) GetDependents() []events.ID {
	return slices.Clone(tn.dependents)
}

func (tn *TailCallNode) addDependent(dependent events.ID) {
	tn.dependents = append(tn.dependents, dependent)
}

// removeDependent removes the given dependent from the node.
// Returns true if the node has no more dependents after removal, false otherwise.
func (tn *TailCallNode) removeDependent(dependent events.ID) bool {
	for i, d := range tn.dependents {
		if d == dependent {
			tn.dependents = append(tn.dependents[:i], tn.dependents[i+1:]...)
			break
		}
	}
	return len(tn.dependents) == 0
}

// GetTCKey returns a unique identifier for this tailcall based on map name and program name.
// Multiple events can share the same map+program combination with different indexes,
// so indexes are merged within the TailCallNode rather than being part of the key.
func GetTCKey(tailCall events.TailCall) string {
	return tailCall.GetMapName() + ":" + tailCall.GetProgName()
}
