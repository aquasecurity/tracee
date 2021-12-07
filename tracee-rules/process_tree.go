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
	tree map[string]ContainerProcessTree
}

func (tree *ProcessTree) getContainerTree(containerID string) (*ContainerProcessTree, error) {
	containerTree, ok := tree.tree[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return &containerTree, nil
}

func (tree *ProcessTree) ProcessExec(event external.Event) error {
	containerTree, _ := tree.getContainerTree(event.ContainerID)
	process, _ := containerTree.GetProcessInfo(event.ParentProcessID)
	process.Cmd = event.Args[2].Value.([]string)
	process.ExecutionBinary = BinaryInfo{
		Path:  event.Args[1].Value.(string),
		Hash:  "",
		Ctime: event.Args[7].Value.(int),
	}
	return nil
}

func (tree *ProcessTree) ProcessFork(event external.Event) error {
	fatherProcess, _ := tree.GetProcessInfo(event.ContainerID, event.HostProcessID)
	process := ProcessInfo{
		InHostIDs: ProcessIDs{
			Pid:  event.HostProcessID,
			Ppid: event.HostParentProcessID,
			Tid:  event.HostThreadID,
		},
		InContainerIDs: ProcessIDs{
			Pid:  event.ProcessID,
			Ppid: event.ParentProcessID,
			Tid:  event.HostThreadID,
		},
		StartTime:     event.Timestamp,
		ParentProcess: fatherProcess,
	}
	fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, &process) // Problematic because will point to the ProcessInfo in the stack and not in the map
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		tree.tree[event.ContainerID] = ContainerProcessTree{
			root: &process, // Problematic because will point to the ProcessInfo in the stack and not in the map
		}
		containerTree, _ = tree.getContainerTree(event.ContainerID)
	}
	containerTree.tree[event.ParentProcessID] = process
	return nil
}

func (tree *ProcessTree) GetProcessInfo(containerID string, processID int) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.GetProcessInfo(processID)
}

func (tree *ProcessTree) GetContainerRoot(containerID string) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.root, nil
}
