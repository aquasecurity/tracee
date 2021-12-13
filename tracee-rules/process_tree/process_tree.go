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

// GetContainerRoot return the first recorded process in a container
func (tree *ProcessTree) GetContainerRoot(containerID string) (*ProcessInfo, error) {
	containerTree, err := tree.getContainerTree(containerID)
	if err != nil {
		return nil, err
	}
	return containerTree.root, nil
}

// ProcessEvent update the process tree according to arriving event
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

// processExec fill the fields of the process according to exec information.
// It also fills the missing information from the fork.
func (tree *ProcessTree) processExec(event external.Event) error {
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		return err
	}
	process, err := containerTree.GetProcessInfo(event.HostThreadID)
	if err != nil {
		return err
	}
	execArgv, err := getArgumentByName(event, "argv")
	if err != nil {
		return err
	}
	var ok bool
	process.Cmd, ok = execArgv.Value.([]string)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			execArgv.Name,
			execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			execPathName.Name,
			execPathName.Type)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return err
	}
	ctime64, ok := execCtime.Value.(uint64)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			execCtime.Name,
			execCtime.Type)
	}
	ctime := uint(ctime64)
	process.ExecutionBinary = BinaryInfo{
		Path:  pathName,
		Hash:  "",
		Ctime: ctime,
	}
	process.InContainerIDs.Pid = event.ProcessID
	process.InContainerIDs.Tid = event.ThreadID
	return nil
}

// processFork add new process to the tree with all possible information available.
// Notice that the new process ID and TID are not available, and will be collected only upon exec.
func (tree *ProcessTree) processFork(event external.Event) error {
	newProcessHostTIDArgument, err := getArgumentByName(event, "child_tid")
	if err != nil {
		return err
	}
	newProcessHostTID32, ok := newProcessHostTIDArgument.Value.(int32)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			newProcessHostTIDArgument.Name,
			newProcessHostTIDArgument.Value)
	}
	newProcessHostTID := int(newProcessHostTID32)
	fatherProcess, err := tree.GetProcessInfo(event.ContainerID, event.HostProcessID)
	var newProcess ProcessInfo
	if err == nil {
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

// processExit remove references of processes from the tree when the corresponding process exit without children, or
// if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit
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
