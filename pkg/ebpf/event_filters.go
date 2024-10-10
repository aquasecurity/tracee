package ebpf

import (
	"errors"
	"fmt"
	"maps"
	"strconv"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type eventFilterHandler func(t *Tracee, eventFilters map[string]filters.Filter[*filters.StringFilter]) error

var eventFilterHandlers = map[events.ID]eventFilterHandler{
	events.CheckSyscallSource: attachCheckSyscallSourceProbes,
}

// handleEventFilters performs eBPF related actions according to special event filters.
// For example, an event can use one of its filters to populate eBPF maps, or perhaps
// attach eBPF programs according to the filters.
func (t *Tracee) handleEventFilters() error {
	// Iterate through registerd event filter handlers
	for eventID, handler := range eventFilterHandlers {
		// Make sure this event is selected
		if _, err := t.eventsDependencies.GetEvent(eventID); err != nil {
			continue
		}

		// Construct filters for this event
		eventFilters := map[string]filters.Filter[*filters.StringFilter]{}
		for it := t.policyManager.CreateAllIterator(); it.HasNext(); {
			p := it.Next()
			f := p.DataFilter.GetEventFilters(eventID)
			if len(f) == 0 {
				continue
			}
			maps.Copy(eventFilters, f)
		}
		if len(eventFilters) == 0 {
			continue
		}

		// Call handler
		err := handler(t, eventFilters)
		if err != nil {
			logger.Errorw("Failed to handle event filters", "event", events.Core.GetDefinitionByID(eventID).GetName(), "error", err)
			err = t.eventsDependencies.RemoveEvent(eventID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func attachCheckSyscallSourceProbes(t *Tracee, eventFilters map[string]filters.Filter[*filters.StringFilter]) error {
	// Get syscalls to trace
	syscallsFilter, ok := eventFilters["syscall"].(*filters.StringFilter)
	if !ok {
		return nil
	}
	syscalls := make([]string, 0)
	for _, entry := range syscallsFilter.Equal() {
		syscallID, err := strconv.Atoi(entry)
		if err != nil {
			return err
		}
		if !events.Core.IsDefined(events.ID(syscallID)) {
			return fmt.Errorf("syscall id %d is not defined", syscallID)
		}
		syscalls = append(syscalls, events.Core.GetDefinitionByID(events.ID(syscallID)).GetName())
	}

	// Create probe group
	probeMap := make(map[probes.Handle]probes.Probe)
	for i, syscall := range syscalls {
		probeMap[probes.Handle(i)] = probes.NewTraceProbe(probes.SyscallEnter, syscall, "check_syscall_source")
	}
	t.checkSyscallSourceProbes = probes.NewProbeGroup(t.bpfModule, probeMap)

	// Attach probes
	for i, syscall := range syscalls {
		if err := t.checkSyscallSourceProbes.Attach(probes.Handle(i), t.kernelSymbols); err != nil {
			var errs error
			errs = errors.Join(errs, fmt.Errorf("failed to attach check_syscall_source probe for syscall %s: %v", syscall, err))
			if err := t.checkSyscallSourceProbes.DetachAll(); err != nil {
				errs = errors.Join(errs, err)
			}
			if err := t.eventsDependencies.RemoveEvent(events.CheckSyscallSource); err != nil {
				errs = errors.Join(errs, err)
			}
			return errs
		}
	}

	return nil
}
