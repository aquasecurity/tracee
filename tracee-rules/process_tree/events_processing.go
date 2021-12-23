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
