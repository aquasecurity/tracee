package process_tree

import (
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// processForkEvent add new process to process tree if new process created, or update process threads if new thread
// created. Because the fork at start is only a copy of the father, the important information regarding of the
// process information and binary will be collected upon execve.
func (tree *ProcessTree) processForkEvent(event external.Event) error {
	newProcessInHostIDs, err := parseForkInHostIDs(event)
	if err != nil {
		return err
	}

	if newProcessInHostIDs.Pid == newProcessInHostIDs.Tid {
		return tree.processMainThreadFork(event, newProcessInHostIDs)
	} else {
		return tree.processThreadFork(event, newProcessInHostIDs)
	}
}

// processMainThreadFork add new process to the tree with all possible information available.
// Notice that the new process information is a duplicate of the father, until an exec will occur.
func (tree *ProcessTree) processMainThreadFork(event external.Event, inHostIDs types.ProcessIDs) error {
	inContainerIDs, err := parseForkInContainerIDs(event)
	if err != nil {
		return err
	}

	newProcess, npErr := tree.GetProcessInfo(inHostIDs.Pid)
	// If it is a new process or if for some reason the existing process is a result of lost exit event
	if npErr != nil ||
		newProcess.Status.Contains(uint32(types.Forked)) {
		newProcess = tree.addNewForkedProcess(event, inHostIDs, inContainerIDs)
	}

	// If exec did not happened yet, add binary information of parent
	if !newProcess.Status.Contains(uint32(types.Executed)) {
		tree.copyParentBinaryInfo(newProcess)
	}
	if newProcess.Status.Contains(uint32(types.HollowParent)) {
		fillHollowProcessInfo(
			newProcess,
			inHostIDs,
			inContainerIDs,
			event.ContainerID,
			event.ProcessName,
		)
	}

	newProcess.StartTime = event.Timestamp
	newProcess.Status.Add(uint32(types.Forked))
	return nil
}

// processThreadFork fill process information if lacking, and add to thread count.
func (tree *ProcessTree) processThreadFork(event external.Event, newInHostIDs types.ProcessIDs) error {
	newProcess, npErr := tree.GetProcessInfo(event.HostProcessID)
	if npErr != nil {
		// In this case, calling thread is another thread of the process and we have normal general information on it
		newProcess = tree.addGeneralEventProcess(event)
		tree.generateParentProcess(newProcess)
	} else {
		if newProcess.Status.Contains(uint32(types.HollowParent)) {
			fillHollowProcessInfo(
				newProcess,
				types.ProcessIDs{
					Pid:  event.HostProcessID,
					Ppid: event.HostParentProcessID,
					Tid:  event.HostProcessID, // The process TID should be the same as the PID
				},
				types.ProcessIDs{
					Pid:  event.ProcessID,
					Ppid: event.ParentProcessID,
					Tid:  event.ProcessID, // The process TID should be the same as the PID
				},
				event.ProcessName,
				event.ContainerID,
			)
		}

		exist := false
		for _, tid := range newProcess.ExistingThreads {
			if newInHostIDs.Tid == tid {
				exist = true
				break
			}
		}
		if !exist {
			newProcess.ExistingThreads = append(newProcess.ExistingThreads, event.HostThreadID)
		}
	}
	return nil
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

func (tree *ProcessTree) addNewForkedProcess(event external.Event, inHostIDs types.ProcessIDs, inContainerIDs types.ProcessIDs) *processNode {
	newProcess := &processNode{
		ProcessName:     event.ProcessName,
		InHostIDs:       inHostIDs,
		InContainerIDs:  inContainerIDs,
		ContainerID:     event.ContainerID,
		StartTime:       event.Timestamp,
		IsAlive:         true,
		Status:          *roaring.BitmapOf(uint32(types.Forked), uint32(types.GeneralCreated)),
		ExistingThreads: []int{inHostIDs.Tid},
	}
	if newProcess.InContainerIDs.Ppid != 0 &&
		newProcess.InHostIDs.Pid != newProcess.InHostIDs.Ppid { // Prevent looped references
		fatherProcess, err := tree.GetProcessInfo(newProcess.InHostIDs.Ppid)
		if err == nil {
			newProcess.ParentProcess = fatherProcess
			fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, newProcess)
		}
	}
	// This will delete old instance if its exit was missing
	tree.processes[inHostIDs.Pid] = newProcess
	return newProcess
}

func (tree *ProcessTree) copyParentBinaryInfo(p *processNode) {
	if p.Status.Contains(uint32(types.Forked)) {
		fatherProcess, err := tree.GetProcessInfo(p.InHostIDs.Ppid)
		if err == nil {
			p.ExecutionBinary = fatherProcess.ExecutionBinary
			p.Cmd = fatherProcess.Cmd
		}
	}
}
