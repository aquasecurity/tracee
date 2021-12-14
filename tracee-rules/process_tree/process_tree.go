package process_tree

import (
	"fmt"
)

type containerProcessTree struct {
	Root *ProcessInfo
}

type ProcessTree struct {
	containers         map[string]*containerProcessTree
	tree               map[int]*ProcessInfo
	deadProcessesCache []int
}

func (tree *ProcessTree) GetProcessInfo(threadID int) (*ProcessInfo, error) {
	process, ok := tree.tree[threadID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return process, nil
}

// GetContainerRoot return the first recorded process in a container
func (tree *ProcessTree) GetContainerRoot(containerID string) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.Root, nil
}

// GetProcessLineage returns list of processes starting with the ID matching events back to the root of the container
// or oldest registered ancestor in the container (if root is missing)
func (tree *ProcessTree) GetProcessLineage(threadID int) (ProcessLineage, error) {
	process, err := tree.GetProcessInfo(threadID)
	if err != nil {
		return nil, err
	}
	var lineage ProcessLineage
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
