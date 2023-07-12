package proctree

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessEvent update the process tree according to arriving event
func (tree *ProcessTree) ProcessEvent(traceeEvent *trace.Event) error {
	switch events.ID(traceeEvent.EventID) {
	case events.SchedProcessFork:
		return tree.ProcessForkEvent(traceeEvent)
	case events.SchedProcessExec:
		return tree.ProcessExecEvent(traceeEvent)
	case events.SchedProcessExit:
		return tree.ProcessExitEvent(traceeEvent)
	case events.Exit, events.InitNamespaces, events.HiddenKernelModule:
		return nil
	default:
		return tree.processGeneralEvent(traceeEvent)
	}
}

// processGeneralEvent fills process information with the data which resides in every event.
// Warning: there are events with fake process information, because they are originated from
// user mode. DO NOT call this function with these events, as it will corrupt the process tree.
func (tree *ProcessTree) processGeneralEvent(event *trace.Event) error {
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		process, err = tree.addGeneralEventProcess(event)
		if err != nil {
			return err
		}
	}
	process.setGeneralInfoFromEventOnce(event)
	_, err = tree.addGeneralEventThread(event)
	if err != nil {
		return err
	}
	process.mutex.RLock()
	parent := process.getParent()
	process.mutex.RUnlock()
	if parent == nil {
		_, err = tree.generateParentProcess(event.HostParentProcessID, event.ParentProcessID, process)
		if err != nil {
			return err
		}
	}
	return nil
}
