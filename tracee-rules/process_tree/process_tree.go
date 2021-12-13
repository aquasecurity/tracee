package process_tree

import (
	"fmt"
)

type ProcessTree struct {
	tree map[string]*containerProcessTree
}

func (tree *ProcessTree) GetProcessInfo(containerID string, threadID int) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.GetProcessInfo(threadID)
}

// GetContainerRoot return the first recorded process in a container
func (tree *ProcessTree) GetContainerRoot(containerID string) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.root, nil
}

func (tree *ProcessTree) getContainerTree(containerID string) (*containerProcessTree, error) {
	containerTree, ok := tree.tree[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return containerTree, nil
}
