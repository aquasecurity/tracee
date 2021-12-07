package main

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
)

type ProcessIDs struct {
	Pid  int
	Ppid int
	Tid  int
}

type BinaryInfo struct {
	Path  string
	Hash  string
	Ctime int
}

type ProcessInfo struct {
	InContainerIDs  ProcessIDs
	InHostIDs       ProcessIDs
	ProcessName     string
	Cmd             []string
	ExecutionBinary BinaryInfo
	StartTime       int
	ParentProcess   *ProcessInfo
	ChildProcesses  []*ProcessInfo
}

type ContainerProcessTree struct {
	tree map[int]ProcessInfo
	root *ProcessInfo
}

func (tree *ContainerProcessTree) GetProcessInfo(processID int) (*ProcessInfo, error) {
	processInfo, ok := tree.tree[processID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return &processInfo, nil
}

type ProcessTree struct {
	tree map[int]ContainerProcessTree
}

func (tree *ProcessTree) getContainerTree(containerID int) (*ContainerProcessTree, error) {
	containerTree, ok := tree.tree[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return &containerTree, nil
}

func (tree *ProcessTree) InsertProcess(event external.Event) error {
	return nil
}

func (tree *ProcessTree) GetProcessInfo(containerID int, processID int) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.GetProcessInfo(processID)
}

func (tree *ProcessTree) GetContainerRoot(containerID int) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.root, nil
}
