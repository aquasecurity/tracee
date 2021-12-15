package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type containerProcessTree struct {
	Root *types.ProcessInfo
}

type ProcessTree struct {
	containers         map[string]*containerProcessTree
	tree               map[int]*types.ProcessInfo
	deadProcessesCache []int
}

func (tree *ProcessTree) GetProcessInfo(threadID int) (*types.ProcessInfo, error) {
	process, ok := tree.tree[threadID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return process, nil
}

// GetContainerRoot return the first recorded process in a container
func (tree *ProcessTree) GetContainerRoot(containerID string) (*types.ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.Root, nil
}

// GetProcessLineage returns list of processes starting with the ID matching events back to the root of the container
// or oldest registered ancestor in the container (if root is missing)
func (tree *ProcessTree) GetProcessLineage(threadID int) (types.ProcessLineage, error) {
	process, err := tree.GetProcessInfo(threadID)
	if err != nil {
		return nil, err
	}
	var lineage types.ProcessLineage
	for process != nil {
		lineage = append(lineage, *process)
		process = process.ParentProcess
	}
	return lineage, nil
}

func (tree *ProcessTree) getContainerTree(containerID string) (*containerProcessTree, error) {
	containerTree, ok := tree.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return containerTree, nil
}
