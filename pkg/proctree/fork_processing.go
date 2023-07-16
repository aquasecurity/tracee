package proctree

import (
	"time"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

type taskIds struct {
	Pid  int
	Tid  int
	Ppid int
}

// ProcessForkEvent add new process to process tree if new process created,
// or update process threads if new thread created.
// Because the fork at start is only a copy of the parent,
// the important information regarding of the process information and binary will be collected
// upon execve.
func (tree *ProcessTree) ProcessForkEvent(event *trace.Event) error {
	err := tree.processGeneralEvent(event)
	if err != nil {
		return err
	}

	newHostIds, err := parseForkHostIds(event)
	if err != nil {
		return err
	}
	newNsIds, err := parseForNsIds(event)
	if err != nil {
		return err
	}

	if newHostIds.Pid == newHostIds.Tid {
		err = tree.addForkProcess(event, newHostIds, newNsIds)
		if err != nil {
			return err
		}
	}
	return tree.addForkThread(event, newHostIds, newNsIds)
}

// addForkProcess create a new process using fork event and the IDs given to the new process
// Notice that the new process information is a duplicate of the parent, until an exec will occur.
func (tree *ProcessTree) addForkProcess(event *trace.Event, newInHostIds taskIds, newInNsIds taskIds) error {
	newProcess, err := tree.getProcess(newInHostIds.Pid)
	// If it is a new process or if for some reason the existing process is a result of lost exit
	// event
	if err != nil ||
		newProcess.getForkTime().UnixNano() != 0 {
		tree.removeProcessFromTree(newInHostIds.Pid, true)
		newProcess, err = tree.newForkedProcessNode(newInHostIds, newInNsIds)
		if err != nil {
			return err
		}
	}
	eventTimestamp := time.Unix(0, int64(event.Timestamp))
	newProcess.mutex.Lock()
	tree.copyParentBinaryInfo(eventTimestamp, newProcess)

	newProcess.setGeneralInfoOnceUnprotected(
		newInNsIds.Pid,
		event.UserID,
		event.Container.ID,
	)

	newProcess.setForkTime(eventTimestamp)
	newProcess.mutex.Unlock()
	return nil
}

// addForkThread create a new thread using fork event and the IDs given to the new thread
func (tree *ProcessTree) addForkThread(event *trace.Event, newInHostIds taskIds, newInNsIds taskIds) error {
	process, err := tree.getProcess(newInHostIds.Pid)
	if err != nil {
		return err
	}
	process.mutex.Lock()
	newThread, err := tree.getOrCreateProcessThreadNode(process, newInHostIds.Tid)
	if err != nil {
		process.mutex.Unlock()
		return err
	}

	processExitTime := process.getExitTime()
	process.mutex.Unlock()
	eventTimestamp := time.Unix(0, int64(event.Timestamp))
	newThread.mutex.Lock()
	newThread.setForkTime(eventTimestamp)
	newThread.setName(eventTimestamp, event.ProcessName)
	newThread.setGeneralInfoOnceUnprotected(
		newInNsIds.Tid,
		event.ProcessName,
		namespacesIds{
			pid:   event.PIDNS,
			mount: event.MountNS,
		},
		processExitTime,
	)
	newThread.mutex.Unlock()
	return nil
}

// parseForkHostIds gets the new forked process Ids in the host PId namespace
func parseForkHostIds(event *trace.Event) (taskIds, error) {
	var inHostIds taskIds
	var err error
	inHostIds.Pid, err = helpers.GetTraceeIntArgumentByName(*event, "child_pid")
	if err != nil {
		return inHostIds, err
	}
	inHostIds.Tid, err = helpers.GetTraceeIntArgumentByName(*event, "child_tid")
	if err != nil {
		return inHostIds, err
	}
	inHostIds.Ppid = event.HostProcessID

	return inHostIds, nil
}

// parseForNsIds get the new forked process Ids in the process PId namespace
func parseForNsIds(event *trace.Event) (taskIds, error) {
	var inContainerIds taskIds
	var err error
	inContainerIds.Pid, err = helpers.GetTraceeIntArgumentByName(*event, "child_ns_pid")
	if err != nil {
		return inContainerIds, err
	}
	inContainerIds.Tid, err = helpers.GetTraceeIntArgumentByName(*event, "child_ns_tid")
	if err != nil {
		return inContainerIds, err
	}
	inContainerIds.Ppid = event.ProcessID

	return inContainerIds, nil
}

// newForkedProcessNode create a new process node in the process tree.
// It will connect it to its parent process if it is not the first process in the container.
func (tree *ProcessTree) newForkedProcessNode(
	inHostIds taskIds,
	inContainerIds taskIds,
) (*processNode, error) {
	newProcess, err := tree.newProcessNode(inHostIds.Pid)
	if err != nil {
		return nil, err
	}
	newProcess.mutex.Lock()
	defer newProcess.mutex.Unlock()

	if inContainerIds.Ppid != 0 &&
		inHostIds.Pid != inHostIds.Ppid { // Prevent looped references
		parentProcess, err := tree.getProcess(inHostIds.Ppid)
		if err == nil {
			newProcess.connectParent(parentProcess)
			parentProcess.mutex.Lock()
			parentProcess.connectChild(newProcess)
			parentProcess.mutex.Unlock()
		}
	}
	return newProcess, nil
}

// copyParentBinaryInfo copies the binary information of the parent node at given time if exist to
// the given process node.
// This is useful for forked processes, as they have the same binary as parent process until exec
// is invoked.
func (tree *ProcessTree) copyParentBinaryInfo(copyTime time.Time, p *processNode) {
	parentProcess := p.getParent()
	if parentProcess == nil {
		return
	}
	parentProcess.mutex.RLock()
	parentExecInfo := parentProcess.getExecInfo(copyTime)
	parentProcess.mutex.RUnlock()
	p.setDefaultExecInfo(parentExecInfo)
}
