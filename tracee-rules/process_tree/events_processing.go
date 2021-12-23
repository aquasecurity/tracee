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
		fillHollowParentProcessGeneralEvent(process, event)
	}
	process.ExecutionBinary, process.Cmd, err = parseExecArguments(event)
	if err != nil {
		return err
	}
	process.ProcessName = event.ProcessName

	if process.Status == types.Forked ||
		process.Status == types.Completed {
		process.Status = types.Completed
	} else {
		process.Status = types.Executed
	}
	return nil
}

// processFork add new process to the tree with all possible information available.
// Notice that the new process ID and TID are not available, and will be collected only upon exec.
func (tree *ProcessTree) processFork(event external.Event) error {
	newProcessInHostIDs, err := parseForkInHostIDs(event)
	if err != nil {
		return err
	}
	newProcessInContainerIDs, err := parseForkInContainerIDs(event)
	if err != nil {
		return err
	}

	isMainThread := newProcessInHostIDs.Pid == newProcessInHostIDs.Tid
	newProcess, npErr := tree.GetProcessInfo(newProcessInHostIDs.Pid)
	if isMainThread {
		// If it is a new process or if for some reason the existing process is a result of lost exit event
		if npErr != nil ||
			newProcess.Status == types.Completed ||
			newProcess.Status == types.Forked {
			newProcess = tree.addNewForkedProcess(event, newProcessInHostIDs, newProcessInContainerIDs)
		}

		// If exec did not happened yet, add binary information of parent
		if newProcess.Status == types.Forked {
			tree.copyParentBinaryInfo(newProcess)
		}

	} else {
		if npErr != nil {
			// In this case, calling thread is another thread of the process and we have normal general information on it
			newProcess = tree.addGeneralEventProcess(event)
			tree.generateParentProcess(newProcess)
		} else {
			newProcess.ThreadsCount += 1
		}
	}
	if newProcess.Status == types.HollowParent {
		fillHollowProcessInfo(
			newProcess,
			newProcessInHostIDs,
			newProcessInContainerIDs,
			event.ContainerID,
			event.ProcessName,
		)
	}
	if isMainThread {
		newProcess.StartTime = event.Timestamp
		// Because this is the main thread, it was not forked until now so it can't be completed yet
		if newProcess.Status == types.Executed {
			newProcess.Status = types.Completed
		} else {
			newProcess.Status = types.Forked
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
	process.ThreadsCount -= 1
	// In case of concurrent processing, this check will be problematic
	if process.ThreadsCount <= 0 {
		process.IsAlive = false
		// Remove process and all dead ancestors so only processes with alive descendants will remain.
		if len(process.ChildProcesses) == 0 {
			container, err := tree.getContainerTree(event.ContainerID)
			if err != nil {
				return err
			}
			cp := process
			for {
				tree.cachedDeleteProcess(cp.InHostIDs.Pid)
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
	}
	return nil
}

// processDefaultEvent tries to expand the process tree in case of lost events or missing start information
func (tree *ProcessTree) processDefaultEvent(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		process = tree.addGeneralEventProcess(event)
	} else if process.Status == types.HollowParent {
		fillHollowParentProcessGeneralEvent(process, event)
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
		ContainerID:  event.ContainerID,
		ThreadsCount: 1,
		IsAlive:      true,
		Status:       types.GeneralCreated,
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

func fillHollowParentProcessGeneralEvent(p *types.ProcessInfo, event external.Event) {
	fillHollowProcessInfo(
		p,
		types.ProcessIDs{Pid: event.HostProcessID, Tid: event.HostThreadID, Ppid: event.HostProcessID},
		types.ProcessIDs{Pid: event.ProcessID, Tid: event.ThreadID, Ppid: event.ProcessID},
		event.ProcessName,
		event.ContainerID,
	)
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

func (tree *ProcessTree) cachedDeleteProcess(pid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, pid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dpid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		delete(tree.tree, dpid)
	}
}

func (tree *ProcessTree) emptyProcessCache() {
	for _, dpid := range tree.deadProcessesCache {
		delete(tree.tree, dpid)
	}
	tree.deadProcessesCache = []int{}
	return
}

func (tree *ProcessTree) addNewForkedProcess(event external.Event, inHostIDs types.ProcessIDs, inContainerIDs types.ProcessIDs) *types.ProcessInfo {
	newProcess := &types.ProcessInfo{
		ProcessName:    event.ProcessName,
		InHostIDs:      inHostIDs,
		InContainerIDs: inContainerIDs,
		ContainerID:    event.ContainerID,
		StartTime:      event.Timestamp,
		IsAlive:        true,
		Status:         types.Forked,
		ThreadsCount:   1,
	}
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		containerTree = &containerProcessTree{
			Root: newProcess,
		}
		tree.containers[event.ContainerID] = containerTree
	}
	if newProcess.InContainerIDs.Ppid != 0 {
		fatherProcess, err := tree.GetProcessInfo(newProcess.InHostIDs.Ppid)
		if err == nil {
			newProcess.ParentProcess = fatherProcess
			fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, newProcess)
		}
	} else {
		containerTree.Root = newProcess
	}
	// This will delete old instance if its exit was missing
	tree.tree[inHostIDs.Pid] = newProcess
	return newProcess
}

func (tree *ProcessTree) copyParentBinaryInfo(p *types.ProcessInfo) {
	if p.Status == types.Forked {
		fatherProcess, err := tree.GetProcessInfo(p.InHostIDs.Ppid)
		if err == nil {
			p.ExecutionBinary = fatherProcess.ExecutionBinary
			p.Cmd = fatherProcess.Cmd
		}
	}
}

func parseForkInHostIDs(event external.Event) (types.ProcessIDs, error) {
	var inHostIDs types.ProcessIDs
	var err error
	inHostIDs.Pid, err = parseInt32Field(event, "child_pid")
	if err != nil {
		return inHostIDs, err
	}
	inHostIDs.Tid, err = parseInt32Field(event, "child_tid")
	if err != nil {
		return inHostIDs, err
	}
	inHostIDs.Ppid = event.HostProcessID

	return inHostIDs, nil
}

func parseForkInContainerIDs(event external.Event) (types.ProcessIDs, error) {
	var inContainerIDs types.ProcessIDs
	var err error
	inContainerIDs.Pid, err = parseInt32Field(event, "child_ns_pid")
	if err != nil {
		return inContainerIDs, err
	}
	inContainerIDs.Tid, err = parseInt32Field(event, "child_ns_tid")
	if err != nil {
		return inContainerIDs, err
	}
	inContainerIDs.Ppid = event.ProcessID

	return inContainerIDs, nil
}

func parseExecArguments(event external.Event) (types.BinaryInfo, []string, error) {
	var binaryInfo types.BinaryInfo
	var cmd []string
	execArgv, err := getArgumentByName(event, "argv")
	if err != nil {
		return binaryInfo, cmd, err
	}
	var ok bool
	cmd, ok = execArgv.Value.([]string)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
			execArgv.Name,
			execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return binaryInfo, cmd, err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
			execPathName.Name,
			execPathName.Type)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return binaryInfo, cmd, err
	}
	ctime64, ok := execCtime.Value.(uint64)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
			execCtime.Name,
			execCtime.Type)
	}
	binaryInfo = types.BinaryInfo{
		Path:  pathName,
		Hash:  "",
		Ctime: uint(ctime64),
	}
	return binaryInfo, cmd, nil
}

func parseInt32Field(event external.Event, fieldName string) (int, error) {
	argument, err := getArgumentByName(event, fieldName)
	if err != nil {
		return 0, err
	}
	argumentValue32, ok := argument.Value.(int32)
	if !ok {
		return 0, fmt.Errorf("invalid type of argument '%s' - %T",
			argument.Name,
			argument.Value)
	}
	return int(argumentValue32), nil
}

func fillHollowProcessInfo(
	p *types.ProcessInfo,
	inHostIDs types.ProcessIDs,
	inContainerIDs types.ProcessIDs,
	processName string,
	containerID string,
) {
	p.InHostIDs = inHostIDs
	p.InContainerIDs = inContainerIDs
	p.ContainerID = containerID
	p.ProcessName = processName
	p.ThreadsCount = 1
	p.IsAlive = true
	p.Status = types.GeneralCreated
}
