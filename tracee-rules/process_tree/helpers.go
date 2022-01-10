package process_tree

import (
	"fmt"
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// addGeneralEventProcess generate a new process with information that could be received from any event from the process
func (tree *ProcessTree) addGeneralEventProcess(event external.Event) *processNode {
	process := &processNode{
		ProcessName: event.ProcessName,
		InHostIDs: types.ProcessIDs{
			Pid:  event.HostProcessID,
			Ppid: event.HostParentProcessID,
		},
		InContainerIDs: types.ProcessIDs{
			Pid:  event.ProcessID,
			Ppid: event.ParentProcessID,
		},
		ContainerID:  event.ContainerID,
		ThreadsExits: map[int]timestamp{},
		IsAlive:      true,
		Status:       *roaring.BitmapOf(uint32(types.GeneralCreated)),
	}
	tree.processes[event.HostProcessID] = process
	return process
}

// generateParentProcess create a parent process of given one from tree if existing or creates new node with best
// effort info
func (tree *ProcessTree) generateParentProcess(process *processNode) *processNode {
	if process.InContainerIDs.Ppid != 0 &&
		process.InHostIDs.Pid != process.InHostIDs.Ppid { // Prevent looped references
		parentProcess, err := tree.GetProcessInfo(process.InHostIDs.Ppid)
		if err != nil {
			parentProcess = &processNode{
				InHostIDs: types.ProcessIDs{
					Pid: process.InHostIDs.Ppid,
				},
				InContainerIDs: types.ProcessIDs{
					Pid: process.InContainerIDs.Ppid,
				},
				Status: *roaring.BitmapOf(uint32(types.HollowParent)),
			}
			tree.processes[parentProcess.InHostIDs.Pid] = parentProcess
		}
		process.ParentProcess = parentProcess
		parentProcess.ChildProcesses = append(parentProcess.ChildProcesses, process)
	}
	return process
}

func fillHollowParentProcessGeneralEvent(p *processNode, event external.Event) {
	fillHollowProcessInfo(
		p,
		threadIDs{ProcessIDs: types.ProcessIDs{Pid: event.HostProcessID, Ppid: event.HostParentProcessID}, Tid: event.HostThreadID},
		types.ProcessIDs{Pid: event.ProcessID, Ppid: event.ParentProcessID},
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
	p *processNode,
	inHostIDs threadIDs,
	inContainerIDs types.ProcessIDs,
	processName string,
	containerID string,
) {
	p.InHostIDs = inHostIDs.ProcessIDs
	p.InContainerIDs = inContainerIDs
	p.ContainerID = containerID
	p.ProcessName = processName
	p.ThreadsExits = map[int]timestamp{}
	p.IsAlive = true
	p.Status.Add(uint32(types.GeneralCreated))
	p.Status.Remove(uint32(types.HollowParent))
}

func (p *processNode) addThreadID(tid int) {
	_, exist := p.ThreadsExits[tid]
	if !exist {
		p.ThreadsExits[tid] = timestamp(0)
	} else if p.IsAlive == false {
		p.ThreadsExits[tid] = p.ExitTime
	}
}
