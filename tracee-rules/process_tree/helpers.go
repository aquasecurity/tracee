package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

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
