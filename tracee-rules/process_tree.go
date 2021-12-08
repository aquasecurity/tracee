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
	execArgv, err := getArgumentByName(event, "argv")
	if err != nil {
		return err
	}
	var ok bool
	process.Cmd, ok = execArgv.Value.([]string)
	if !ok {
		return fmt.Errorf("invalid argument type of argument '%s%", execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return fmt.Errorf("invalid argument type of argument '%s%", execArgv.Name)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return err
	}
	ctime, ok := execCtime.Value.(int)
	if !ok {
		return fmt.Errorf("invalid argument type of argument '%s%", execArgv.Name)
	}
	process.ExecutionBinary = BinaryInfo{
		Path:  pathName,
		Hash:  "",
		Ctime: ctime,
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

// getArgumentByName fetches the argument in event with "Name" that matches argName.
func getArgumentByName(event external.Event, argName string) (external.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return external.Argument{}, fmt.Errorf("argument %s not found", argName)
}
