package ebpf

import (
	"maps"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type eventFilterHandler func(eventFilters map[string]filters.Filter, bpfModule *bpf.Module) error

var eventFilterHandlers = map[events.ID]eventFilterHandler{
	events.CheckSyscallSource: populateMapsCheckSyscallSource,
}

// populateEventFilterMaps populates maps with data from special event filters
func (t *Tracee) populateEventFilterMaps() error {
	// Iterate through registerd event filter handlers
	for eventID, handler := range eventFilterHandlers {
		// Construct filters for this event
		filters := map[string]filters.Filter{}
		for p := range t.config.Policies.Map() {
			f := p.ArgFilter.GetEventFilters(eventID)
			if len(f) == 0 {
				continue
			}
			maps.Copy(filters, f)
		}
		if len(filters) == 0 {
			continue
		}

		// Call handler
		err := handler(filters, t.bpfModule)
		if err != nil {
			logger.Errorw("Failed to handle event filter for event " + events.Core.GetDefinitionByID(eventID).GetName() + ", err: " + err.Error())
			t.cancelEventFromEventState(eventID)
		}
	}
	return nil
}

func populateMapsCheckSyscallSource(eventFilters map[string]filters.Filter, bpfModule *bpf.Module) error {
	// Get syscalls to trace
	syscallsFilter, ok := eventFilters["syscall"].(*filters.StringFilter)
	if !ok {
		return nil
	}
	syscalls := syscallsFilter.Equal()

	// Get map and program for check_syscall_source tailcall
	checkSyscallSourceTail, err := bpfModule.GetMap("check_syscall_source_tail")
	if err != nil {
		return errfmt.Errorf("could not get BPF map \"check_syscall_source_tail\": %v", err)
	}
	checkSyscallSourceProg, err := bpfModule.GetProgram("check_syscall_source")
	if err != nil {
		return errfmt.Errorf("could not get BPF program \"check_syscall_source\": %v", err)
	}
	checkSyscallSourceProgFD := checkSyscallSourceProg.FileDescriptor()
	if checkSyscallSourceProgFD < 0 {
		return errfmt.Errorf("could not get BPF program FD for \"check_syscall_source\": %v", err)
	}

	// Add each syscall to the tail call map
	for _, syscall := range syscalls {
		syscallID, err := strconv.Atoi(syscall)
		if err != nil {
			return errfmt.WrapError(err)
		}

		err = checkSyscallSourceTail.Update(unsafe.Pointer(&syscallID), unsafe.Pointer(&checkSyscallSourceProgFD))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}
