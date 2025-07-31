package dependencies

// Action is a struct representing a request by a watcher function to interact with the tree.
//
// Actions can perform various tasks, including but not limited to modifying the tree.
// Utilizing Actions ensures that operations are executed in the proper order, avoiding
// potential bugs related to operation sequencing. All interactions with the tree which
// might modify the tree should be carried out through Actions, rather than directly
// within a watcher's scope.
type Action interface{}

// CancelNodeAddAction cancels the process of adding a node to the manager.
//
// When this action is executed:
// 1. The specified node is removed from the manager (if it was already added).
// 2. All dependent events that rely on this node will fail to be added.
// 3. When dependent events fail, they will attempt to use fallback dependencies if available.
// 4. If no fallback dependencies are available, the dependent events will also be removed.
// 5. Any dependencies that are no longer referenced by other nodes are removed.
//
// This creates a cascade effect where cancelling one node can cause multiple
// dependent events to either use alternative dependencies or be removed entirely.
//
// Note:
// - This action does not prevent other watchers from being notified.
// - Dependent events will try fallback mechanisms before being removed.
// - This is different from FailNodeAddAction: the cancelled node itself will not try to use its own fallbacks.
// - All other effects (dependent events trying fallbacks, cleanup of unused dependencies) are the same as FailNodeAddAction.
//
// It is recommended to use CancelNodeAddAction instead of directly calling RemoveEvent
// to ensure that the cancellation and fallback processes are handled in the correct order.
type CancelNodeAddAction struct {
	Reason error
}

func NewCancelNodeAddAction(reason error) *CancelNodeAddAction {
	return &CancelNodeAddAction{Reason: reason}
}

// FailNodeAddAction marks the addition of a node as failed in the manager.
//
// This action is used to indicate that the process of adding a node has encountered
// an error or failure condition. When this action is executed:
// 1. The node addition process is marked as failed.
// 2. The failure reason is recorded for debugging and error handling purposes.
// 3. Fallback mechanisms are triggered to attempt alternative dependency configurations.
// 4. If fallbacks are available, the system will try to use them instead of completely failing.
// 5. Any dependencies that are no longer referenced by other nodes are removed.
//
// The failure reason should provide clear information about what went wrong during
// the node addition process, which can be useful for:
// - Debugging and troubleshooting
// - Error reporting and logging
// - Understanding why fallback mechanisms were triggered
// - Notifying other components about the failure
//
// Note:
// - This action triggers fallback mechanisms, unlike CancelNodeAddAction which causes immediate removal.
// - If fallbacks are available, the dependent event may still be added successfully using alternative dependencies.
// - If no fallbacks are available, the dependent event will also fail.
// - It is important to provide a meaningful error reason for proper error handling.
type FailNodeAddAction struct {
	Reason error
}

// NewFailNodeAddAction creates a new FailNodeAddAction with the specified failure reason.
//
// The reason parameter should contain a descriptive error message explaining why
// the node addition failed. This information will be used for error handling,
// debugging, and potentially for user-facing error messages.
func NewFailNodeAddAction(reason error) *FailNodeAddAction {
	return &FailNodeAddAction{Reason: reason}
}
