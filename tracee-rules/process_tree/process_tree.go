package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
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

func (tree *ProcessTree) GetContainerRoot(containerID string) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.root, nil
}

func (tree *ProcessTree) ProcessEvent(event external.Event) error {
	switch event.EventName {
	case "sched_process_fork":
		return tree.processFork(event)
	case "sched_process_exec":
		return tree.processExec(event)
	case "sched_process_exit":
		return tree.processExit(event)
	default:
		return nil
	}
}

func (tree *ProcessTree) processExec(event external.Event) error {
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		return err
	}
	process, _ := containerTree.GetProcessInfo(event.HostThreadID)
	execArgv, err := getArgumentByName(event, "argv")
	if err != nil {
		return err
	}
	var ok bool
	process.Cmd, ok = execArgv.Value.([]string)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s'", execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s'", execArgv.Name)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return err
	}
	ctime, ok := execCtime.Value.(int)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s'", execArgv.Name)
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

func (tree *ProcessTree) processFork(event external.Event) error {
	newProcessHostTIDArgument, err := getArgumentByName(event, "child_tid")
	if err != nil {
		return err
	}
	newProcessHostTID, ok := newProcessHostTIDArgument.Value.(int)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s'", newProcessHostTIDArgument.Name)
	}
	fatherProcess, _ := tree.GetProcessInfo(event.ContainerID, newProcessHostTID)
	var newProcess ProcessInfo
	if fatherProcess != nil {
		newProcess = *fatherProcess
		newProcess.ParentProcess = fatherProcess
		fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, &newProcess)
	}
	newProcess.ProcessName = event.ProcessName
	newProcess.InHostIDs = ProcessIDs{
		Pid:  newProcessHostTID,
		Ppid: event.HostProcessID,
		Tid:  newProcessHostTID,
	}
	newProcess.InContainerIDs = ProcessIDs{
		Ppid: event.ProcessID,
	}
	newProcess.StartTime = event.Timestamp
	newProcess.IsAlive = true

	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		containerTree = &containerProcessTree{
			tree: make(map[int]*ProcessInfo),
			root: &newProcess,
		}
		tree.tree[event.ContainerID] = containerTree
	}
	containerTree.tree[newProcessHostTID] = &newProcess
	return nil
}

func (tree *ProcessTree) processExit(event external.Event) error {
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
			if cp.ParentProcess == nil {
				delete(tree.tree, event.ContainerID)
				if len(containerTree.tree) > 0 {
					return fmt.Errorf("root process of container exited without children, but container still has recorded processes")
				}
				break
			}
			if cp.ParentProcess.IsAlive {
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

// getArgumentByName fetches the argument in event with "Name" that matches argName.
func getArgumentByName(event external.Event, argName string) (external.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return external.Argument{}, fmt.Errorf("argument %s not found", argName)
}

func (tree *ProcessTree) getContainerTree(containerID string) (*containerProcessTree, error) {
	containerTree, ok := tree.tree[containerID]
	if !ok {
		return nil, fmt.Errorf("no container with given ID is recorded")
	}
	return containerTree, nil
}
