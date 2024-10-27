package ebpf

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type eventParameterHandler func(t *Tracee, eventParams []map[string]filters.Filter[*filters.StringFilter]) error

var eventParameterHandlers = map[events.ID]eventParameterHandler{
	events.SuspiciousSyscallSource: attachSuspiciousSyscallSourceProbes,
}

// handleEventParameters performs initialization actions according to event parameters,
// specified using policies or the command line as event arguments.
// For example, an event can use one of its parameters to populate eBPF maps,
// or perhaps attach eBPF programs according to the parameters.
func (t *Tracee) handleEventParameters() error {
	// Iterate through registerd event parameter handlers
	for eventID, handler := range eventParameterHandlers {
		// Make sure this event is selected
		if _, err := t.eventsDependencies.GetEvent(eventID); err != nil {
			continue
		}
		// Get the event parameters for all policies.
		// Event parameters are simply event data filters, interpreted according to the
		// specific event and filter in question.
		// While this method of specifying event parameters is convenient, it may cause
		// confusion as it abuses the filter system.
		// TODO: in the future, a dedicated event parameter system should be added.
		eventParams := make([]map[string]filters.Filter[*filters.StringFilter], 0)
		for iterator := t.policyManager.CreateAllIterator(); iterator.HasNext(); {
			policy := iterator.Next()
			policyParams := policy.DataFilter.GetEventFilters(eventID)
			if len(policyParams) == 0 {
				continue
			}
			eventParams = append(eventParams, policyParams)
		}
		if len(eventParams) == 0 {
			// No parameters for this event
			continue
		}
		// Call handler
		if err := handler(t, eventParams); err != nil {
			if err := t.eventsDependencies.RemoveEvent(eventID); err != nil {
				logger.Warnw("Failed to remove event from dependencies manager", "remove reason", "failed handling event parameters", "error", err)
			}
			return fmt.Errorf("failed to handle parameters for event %s: %v", events.Core.GetDefinitionByID(eventID).GetName(), err)
		}
	}
	return nil
}

func attachSuspiciousSyscallSourceProbes(t *Tracee, eventParams []map[string]filters.Filter[*filters.StringFilter]) error {
	// Get syscalls to trace
	syscalls := make(map[string]struct{}, 0)
	for _, policyParams := range eventParams {
		syscallsParam, ok := policyParams["syscall"].(*filters.StringFilter)
		if !ok {
			return nil
		}
		for _, entry := range syscallsParam.Equal() {
			syscallID, err := strconv.Atoi(entry)
			if err != nil {
				return err
			}
			if !events.Core.IsDefined(events.ID(syscallID)) {
				return fmt.Errorf("syscall id %d is not defined", syscallID)
			}

			syscallName := events.Core.GetDefinitionByID(events.ID(syscallID)).GetName()
			syscalls[syscallName] = struct{}{}
		}
	}

	// Create probe group
	probeMap := make(map[probes.Handle]probes.Probe)
	i := 0
	for syscallName := range syscalls {
		probeMap[probes.Handle(i)] = probes.NewTraceProbe(probes.SyscallEnter, syscallName, "suspicious_syscall_source")
		i++
	}
	t.suspiciousSyscallSourceProbes = probes.NewProbeGroup(t.bpfModule, probeMap)

	// Attach probes
	i = 0
	for syscallName := range syscalls {
		if err := t.suspiciousSyscallSourceProbes.Attach(probes.Handle(i), t.kernelSymbols); err != nil {
			// Report attachment errors but don't fail, because it may be a syscall that doesn't exist on this system
			logger.Warnw("Failed to attach suspicious_syscall_source kprobe", "syscall", syscallName, "error", err)
		}
		i++
	}

	return nil
}
