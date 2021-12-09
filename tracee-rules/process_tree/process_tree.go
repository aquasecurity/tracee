package process_tree

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
	IsAlive         bool
}

type ContainerProcessTree struct {
	tree map[int]*ProcessInfo
	root *ProcessInfo
}

func (tree *ContainerProcessTree) GetProcessInfo(threadID int) (*ProcessInfo, error) {
	processInfo, ok := tree.tree[threadID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return processInfo, nil
}

type ProcessTree struct {
	tree map[string]*ContainerProcessTree
}

func (tree *ProcessTree) getContainerTree(containerID string) (*ContainerProcessTree, error) {
	containerTree, ok := tree.tree[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return containerTree, nil
}

func (tree *ProcessTree) ProcessExec(event external.Event) error {
	containerTree, _ := tree.getContainerTree(event.ContainerID)
	process, _ := containerTree.GetProcessInfo(event.HostThreadID)
	execArgv, err := getArgumentByName(event, "argv")
	if err != nil {
		return err
	}
	var ok bool
	process.Cmd, ok = execArgv.Value.([]string)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s%", execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s%", execArgv.Name)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return err
	}
	ctime, ok := execCtime.Value.(int)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s%", execArgv.Name)
	}
	process.ExecutionBinary = BinaryInfo{
		Path:  pathName,
		Hash:  "",
		Ctime: ctime,
	}
	process.InContainerIDs.Pid = event.ProcessID
	process.InContainerIDs.Tid = event.ThreadID
	return nil
}

func (tree *ProcessTree) ProcessFork(event external.Event) error {
	newProcessHostTIDArgument, err := getArgumentByName(event, "child_tid")
	if err != nil {
		return err
	}
	newProcessHostTID, ok := newProcessHostTIDArgument.Value.(int)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s%", newProcessHostTIDArgument.Name)
	}
	fatherProcess, _ := tree.GetProcessInfo(event.ContainerID, newProcessHostTID)
	process := ProcessInfo{
		InHostIDs: ProcessIDs{
			Pid:  newProcessHostTID,
			Ppid: event.HostProcessID,
			Tid:  newProcessHostTID,
		},
		InContainerIDs: ProcessIDs{
			Ppid: event.ProcessID,
		},
		StartTime: event.Timestamp,
		IsAlive:   true,
	}
	fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, &process)
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		containerTree = &ContainerProcessTree{
			root: &process,
		}
		tree.tree[event.ContainerID] = containerTree
	}
	containerTree.tree[event.HostThreadID] = &process
	return nil
}

func (tree *ProcessTree) ProcessExit(event external.Event) error {
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		return err
	}
	process, err := containerTree.GetProcessInfo(event.HostThreadID)
	if err != nil {
		return err
	}
	process.IsAlive = false
	// Remove process and all dead ancestors so only processes with alive descendants will remain.
	if len(process.ChildProcesses) == 0 {
		cp := process
		for {
			delete(containerTree.tree, cp.InHostIDs.Tid)
			if cp.ParentProcess == nil || cp.ParentProcess.IsAlive {
				break
			}
			for i, childProcess := range cp.ParentProcess.ChildProcesses {
				if childProcess == cp {
					cp.ParentProcess.ChildProcesses = append(cp.ParentProcess.ChildProcesses[:i],
						cp.ParentProcess.ChildProcesses[i+1:]...)
				}
			}
			cp = cp.ParentProcess
		}
	}
	return nil
}

func (tree *ProcessTree) GetProcessInfo(containerID string, threadID int) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.GetProcessInfo(threadID)
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
