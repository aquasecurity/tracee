package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// ProcessEvent update the process tree according to arriving event
func (tree *ProcessTree) ProcessEvent(event types.Event) error {
	traceeEvent, ok := event.(external.Event)
	if !ok {
		return fmt.Errorf("received event of unsupported type to process - %t", event)
	}
	switch traceeEvent.EventName {
	case "sched_process_fork":
		return tree.processFork(traceeEvent)
	case "sched_process_exec":
		return tree.processExec(traceeEvent)
	case "sched_process_exit":
		return tree.processExit(traceeEvent)
	case "exit":
		return nil
	default:
		return tree.processDefaultEvent(traceeEvent)
	}
}

// processExec fill the fields of the process according to exec information.
// It also fills the missing information from the fork.
func (tree *ProcessTree) processExec(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		process = tree.addGeneralEventProcess(event)
	}
	if process.ParentProcess == nil {
		tree.generateParentProcess(process)
	}
	if process.Status == types.HollowParent {
		fillHollowParentProcessGeneral(process, event)
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
	process.ExecutionBinary = types.BinaryInfo{
		Path:  pathName,
		Hash:  "",
		Ctime: ctime,
	}
	process.InContainerIDs.Pid = event.ProcessID
	process.InContainerIDs.Tid = event.ThreadID
	process.ProcessName = event.ProcessName

	if process.Status == types.Forked {
		process.Status = types.Complete
	} else {
		process.Status = types.Executed
	}
	return nil
}

// processFork add new process to the tree with all possible information available.
// Notice that the new process ID and TID are not available, and will be collected only upon exec.
func (tree *ProcessTree) processFork(event external.Event) error {
	newProcessHostPIDArgument, err := getArgumentByName(event, "child_pid")
	if err != nil {
		return err
	}
	newProcessHostPID32, ok := newProcessHostPIDArgument.Value.(int32)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			newProcessHostPIDArgument.Name,
			newProcessHostPIDArgument.Value)
	}
	newProcessHostPID := int(newProcessHostPID32)
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
	newProcessContainerPIDArgument, err := getArgumentByName(event, "child_ns_pid")
	if err != nil {
		return err
	}
	newProcessContainerPID32, ok := newProcessContainerPIDArgument.Value.(int32)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			newProcessContainerPIDArgument.Name,
			newProcessContainerPIDArgument.Value)
	}
	newProcessContainerPID := int(newProcessContainerPID32)
	newProcessContainerTIDArgument, err := getArgumentByName(event, "child_ns_tid")
	if err != nil {
		return err
	}
	newProcessContainerTID32, ok := newProcessContainerTIDArgument.Value.(int32)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			newProcessContainerTIDArgument.Name,
			newProcessContainerTIDArgument.Value)
	}
	newProcessContainerTID := int(newProcessContainerTID32)
	newProcess, err := tree.GetProcessInfo(newProcessHostTID)
	if err != nil {
		// If the process is already forked by main thread there is no purpose in continuing
		if newProcess.Status == types.Complete ||
			newProcess.Status == types.Forked {
			return nil
		}
		if newProcess.Status == types.HollowParent {
			newProcess.InHostIDs = types.ProcessIDs{
				Pid:  newProcessHostPID,
				Tid:  newProcessHostTID,
				Ppid: event.HostProcessID,
			}
			newProcess.InContainerIDs = types.ProcessIDs{
				Pid:  newProcessContainerPID,
				Tid:  newProcessContainerTID,
				Ppid: event.ProcessID,
			}
			newProcess.ProcessName = event.ProcessName
			newProcess.IsAlive = true
			newProcess.Status = types.GeneralCreated
		}
		// Add fork information if the main thread
		if newProcessHostPID == newProcessHostTID {
			newProcess.StartTime = event.Timestamp
			if newProcess.Status == types.Forked {
				newProcess.Status = types.Complete
			} else {
				newProcess.Status = types.Forked
			}
		}
	} else {
		newProcess = &types.ProcessInfo{
			ProcessName: event.ProcessName,
			InHostIDs: types.ProcessIDs{
				Pid:  newProcessHostTID,
				Ppid: event.HostProcessID,
				Tid:  newProcessHostTID,
			},
			InContainerIDs: types.ProcessIDs{
				Ppid: event.ProcessID,
			},
			ContainerID: event.ContainerID,
			StartTime:   event.Timestamp,
			IsAlive:     true,
			Status:      types.Forked,
		}
		containerTree, err := tree.getContainerTree(event.ContainerID)
		if err != nil {
			containerTree = &containerProcessTree{
				Root: newProcess,
			}
			tree.containers[event.ContainerID] = containerTree
		}
		// This will delete old instance if its exit was missing
		tree.tree[newProcessHostTID] = newProcess
	}

	if newProcess.Status == types.Forked {
		fatherProcess, err := tree.GetProcessInfo(event.HostProcessID)
		if err == nil {
			newProcess.ExecutionBinary = fatherProcess.ExecutionBinary
			newProcess.Cmd = fatherProcess.Cmd
			newProcess.ParentProcess = fatherProcess
			fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, newProcess)
		}
	}

	return nil
}

// processExit remove references of processes from the tree when the corresponding process exit without children, or
// if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit
func (tree *ProcessTree) processExit(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		return err
	}
	process.IsAlive = false
	// Remove process and all dead ancestors so only processes with alive descendants will remain.
	if len(process.ChildProcesses) == 0 {
		container, err := tree.getContainerTree(event.ContainerID)
		if err != nil {
			return err
		}
		cp := process
		for {
			tree.cachedDeleteProcess(cp.InHostIDs.Tid)
			if container.Root == cp {
				delete(tree.containers, event.ContainerID)
			}
			if cp.ParentProcess == nil {
				break
			}
			for i, childProcess := range cp.ParentProcess.ChildProcesses {
				if childProcess == cp {
					cp.ParentProcess.ChildProcesses = append(cp.ParentProcess.ChildProcesses[:i],
						cp.ParentProcess.ChildProcesses[i+1:]...)
				}
				break
			}
			if cp.ParentProcess.IsAlive {
				break
			}
			cp = cp.ParentProcess
		}
	}
	return nil
}

// processDefaultEvent tries to expand the process tree in case of lost events or missing start information
func (tree *ProcessTree) processDefaultEvent(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		process = tree.addGeneralEventProcess(event)
	} else if process.Status == types.HollowParent {
		fillHollowParentProcessGeneral(process, event)
	}
	if process.ParentProcess == nil {
		parentProcess, err := tree.GetProcessInfo(event.HostParentProcessID)
		if err == nil {
			process.ParentProcess = parentProcess
			parentProcess.ChildProcesses = append(parentProcess.ChildProcesses, process)
		} else {
			tree.generateParentProcess(process)
		}
	}
	return nil

}

func (tree *ProcessTree) addGeneralEventProcess(event external.Event) *types.ProcessInfo {
	process := &types.ProcessInfo{
		ProcessName: event.ProcessName,
		InHostIDs: types.ProcessIDs{
			Pid:  event.HostProcessID,
			Ppid: event.HostParentProcessID,
			Tid:  event.HostThreadID,
		},
		InContainerIDs: types.ProcessIDs{
			Pid:  event.ProcessID,
			Ppid: event.ProcessID,
			Tid:  event.ThreadID,
		},
		ContainerID: event.ContainerID,
		IsAlive:     true,
		Status:      types.GeneralCreated,
	}
	tree.tree[event.HostProcessID] = process
	_, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		containerTree := &containerProcessTree{
			Root: process,
		}
		tree.containers[event.ContainerID] = containerTree
	}
	return process
}

// generateParentProcess creates a parent process of given one from tree if existing or creates new node with best
// effort info
func (tree *ProcessTree) generateParentProcess(process *types.ProcessInfo) *types.ProcessInfo {
	if process.InContainerIDs.Ppid != 0 {
		parentProcess, err := tree.GetProcessInfo(process.InHostIDs.Ppid)
		if err != nil {
			parentProcess = &types.ProcessInfo{
				InHostIDs: types.ProcessIDs{
					Pid: process.InHostIDs.Ppid,
				},
				InContainerIDs: types.ProcessIDs{
					Pid: process.InContainerIDs.Ppid,
				},
				Status: types.HollowParent,
			}
		}
		process.ParentProcess = parentProcess
		parentProcess.ChildProcesses = append(parentProcess.ChildProcesses, process)

		croot, _ := tree.GetContainerRoot(process.ContainerID)
		if croot == process {
			tree.containers[process.ContainerID].Root = parentProcess
		}
	}
	return process
}

func fillHollowParentProcessGeneral(p *types.ProcessInfo, event external.Event) {
	p.InHostIDs = types.ProcessIDs{
		Pid:  event.HostProcessID,
		Tid:  event.HostThreadID,
		Ppid: event.HostProcessID,
	}
	p.InContainerIDs = types.ProcessIDs{
		Pid:  event.ProcessID,
		Tid:  event.ThreadID,
		Ppid: event.ProcessID,
	}
	p.ProcessName = event.ProcessName
	p.IsAlive = true
	p.Status = types.GeneralCreated
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

const cachedDeadEvents = 100

func (tree *ProcessTree) cachedDeleteProcess(tid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, tid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dtid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		delete(tree.tree, dtid)
	}
}
