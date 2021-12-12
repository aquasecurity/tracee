package process_tree

import "fmt"

type containerProcessTree struct {
	tree map[int]*ProcessInfo
	root *ProcessInfo
}

func (tree *containerProcessTree) GetProcessInfo(threadID int) (*ProcessInfo, error) {
	processInfo, ok := tree.tree[threadID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return processInfo, nil
}
