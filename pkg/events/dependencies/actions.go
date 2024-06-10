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
// This method will:
// 1. Cancel the addition of the specified node.
// 2. Cancel the addition of all dependent nodes.
// 3. Remove any dependencies that are no longer referenced by other nodes.
//
// The overall effect is similar to calling RemoveEvent directly on the manager,
// but with additional safeguards and order of operations to ensure proper cleanup
// and consistency within the system.
//
// Note:
// - This action does not prevent other watchers from being notified.
// - When the node addition is cancelled, event removal watchers will be invoked to allow for cleanup operations.
//
// It is recommended to use CancelNodeAddAction instead of directly calling RemoveEvent
// to ensure that the cancellation and cleanup processes are handled in the correct order.
type CancelNodeAddAction struct {
	Reason error
}

func NewCancelNodeAddAction(reason error) *CancelNodeAddAction {
	return &CancelNodeAddAction{Reason: reason}
}
