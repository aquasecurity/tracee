package process_tree

import (
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type threadIDs struct {
	types.ProcessIDs
	Tid int
}

// processForkEvent add new process to process tree if new process created, or update process threads if new thread
// created. Because the fork at start is only a copy of the father, the important information regarding of the
// process information and binary will be collected upon execve.
func (tree *ProcessTree) processForkEvent(event external.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}

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
func (tree *ProcessTree) processMainThreadFork(event external.Event, inHostIDs threadIDs) error {
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
			inContainerIDs.ProcessIDs,
			event.ContainerID,
			event.ProcessName,
		)
	}

	newProcess.addThreadID(inHostIDs.Tid)
	newProcess.StartTime = timestamp(event.Timestamp)
	newProcess.Status.Add(uint32(types.Forked))
	return nil
}

// processThreadFork add new invoked thread to process threads.
func (tree *ProcessTree) processThreadFork(event external.Event, newInHostIDs threadIDs) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		return err
	}
	process.addThreadID(newInHostIDs.Tid)
	return nil
}

func parseForkInHostIDs(event external.Event) (threadIDs, error) {
	var inHostIDs threadIDs
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

func parseForkInContainerIDs(event external.Event) (threadIDs, error) {
	var inContainerIDs threadIDs
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

func (tree *ProcessTree) addNewForkedProcess(event external.Event, inHostIDs threadIDs, inContainerIDs threadIDs) *processNode {
	newProcess := &processNode{
		ProcessName:    event.ProcessName,
		InHostIDs:      inHostIDs.ProcessIDs,
		InContainerIDs: inContainerIDs.ProcessIDs,
		ContainerID:    event.ContainerID,
		StartTime:      timestamp(event.Timestamp),
		IsAlive:        true,
		Status:         *roaring.BitmapOf(uint32(types.Forked), uint32(types.GeneralCreated)),
		ThreadsExits:   map[int]timestamp{},
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
