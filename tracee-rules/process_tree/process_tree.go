package process_tree

import (
	"fmt"
)

type containerProcessTree struct {
	Root *ProcessInfo
}

type ProcessTree struct {
	containers map[string]*containerProcessTree
	tree       map[int]*ProcessInfo
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

func (tree *ProcessTree) getContainerTree(containerID string) (*containerProcessTree, error) {
	containerTree, ok := tree.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return containerTree, nil
}
