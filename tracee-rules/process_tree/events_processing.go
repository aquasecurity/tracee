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
		return tree.processForkEvent(traceeEvent)
	case "sched_process_exec":
		return tree.processExecEvent(traceeEvent)
	case "sched_process_exit":
		return tree.processExitEvent(traceeEvent)
	case "exit", "init_namespaces":
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
		process.addThreadID(event.HostThreadID)
	} else if process.Status.Contains(uint32(types.HollowParent)) {
		fillHollowParentProcessGeneralEvent(process, event)
	}
	process.addThreadID(event.HostThreadID)
	if process.ParentProcess == nil {
		tree.generateParentProcess(process)
	}
	return nil

}
