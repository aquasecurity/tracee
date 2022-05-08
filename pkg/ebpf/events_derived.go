package ebpf

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/types/trace"
)

// deriveFn is a function prototype for a function that receives an event as
// argument and may produce a new event if relevant.
// It returns the a derived or empty event, depending on succesful derivation,
// a bool indicating if an event was derived, and an error if one occured.
type deriveFn func(trace.Event) (trace.Event, bool, error)

// Initialize the eventDerivations map.
// Here we declare for each Event (represented through it's ID)
// to which other Events it can be derived and the corresponding function to derive into that Event.
func (t *Tracee) initEventDerivationMap() error {
	t.eventDerivations = map[int32]map[int32]deriveFn{
		CgroupMkdirEventID: {
			ContainerCreateEventID: deriveContainerCreate(t),
		},
		CgroupRmdirEventID: {
			ContainerRemoveEventID: deriveContainerRemoved(t),
		},
		PrintSyscallTableEventID: {
			DetectHookedSyscallsEventID: deriveDetectHookedSyscall(t),
		},
		SchedProcessExecEventID: {
			ProcessCreationEventID: deriveHigherLevelEvents(t),
		},
		SchedProcessExitEventID: {
			ProcessTerminationEventID: deriveHigherLevelEvents(t),
		},
		SecurityInodeUnlinkEventID: {
			FileDeletionEventID: deriveHigherLevelEvents(t),
		},
	}

	return nil
}

// deriveEvent takes a trace.Event and checks if it can derive additional events from it
// as defined by tracee's eventDerivations map.
// The map is initialized in the above function
func (t *Tracee) deriveEvent(event trace.Event) []trace.Event {
	derivatives := []trace.Event{}
	deriveFns := t.eventDerivations[int32(event.EventID)]
	for id, deriveFn := range deriveFns {
		// Don't derive events which were not requested by the user
		if !t.events[id].emit {
			continue
		}

		derivative, derived, err := deriveFn(event)
		if err != nil {
			t.handleError(fmt.Errorf("failed to derive event %d: %v", id, err))
		} else if derived {
			derivatives = append(derivatives, derivative)
		}
	}

	return derivatives
}

// Pipeline function
func (t *Tracee) deriveEvents(ctx context.Context, in <-chan *trace.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case event := <-in:
				out <- event

				// Derive event before parsing its arguments
				derivatives := t.deriveEvent(*event)

				for _, derivative := range derivatives {
					out <- &derivative
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

/*
* Derivation functions:
* Most derivation functions take tracee as a closure argument to track it's runtime state
* Tracee builds it's derivation map from these functions and injects itself as an argument to the closures
* The derivation map is then built with the returned deriveFn functions, which is used in deriveEvents
 */

//Receives a tracee object as a closure argument to track it's containers
//If it receives a cgroup_mkdir event, it can derive a container_create event from it
func deriveContainerCreate(t *Tracee) deriveFn {
	return func(event trace.Event) (trace.Event, bool, error) {
		cgroupId, err := getEventArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return trace.Event{}, false, err
		}

		def := EventsDefinitions[ContainerCreateEventID]
		if info := t.containers.GetCgroupInfo(cgroupId); info.ContainerId != "" {
			de := event
			de.EventID = int(ContainerCreateEventID)
			de.EventName = def.Name
			de.ReturnValue = 0
			de.StackAddresses = make([]uint64, 1)
			de.Args = []trace.Argument{
				{ArgMeta: def.Params[0], Value: info.Runtime},
				{ArgMeta: def.Params[1], Value: info.ContainerId},
				{ArgMeta: def.Params[2], Value: info.Ctime.UnixNano()},
			}
			de.ArgsNum = len(de.Args)

			return de, true, nil
		}

		return trace.Event{}, false, nil
	}
}

//Receives a tracee object as a closure argument to track it's containers
//If it receives a cgroup_rmdir event, it can derive a container_remove event from it
func deriveContainerRemoved(t *Tracee) deriveFn {
	return func(event trace.Event) (trace.Event, bool, error) {
		cgroupId, err := getEventArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return trace.Event{}, false, err
		}

		def := EventsDefinitions[ContainerRemoveEventID]
		if info := t.containers.GetCgroupInfo(cgroupId); info.ContainerId != "" {
			de := event
			de.EventID = int(ContainerRemoveEventID)
			de.EventName = def.Name
			de.ReturnValue = 0
			de.StackAddresses = make([]uint64, 1)
			de.Args = []trace.Argument{
				{ArgMeta: def.Params[0], Value: info.Runtime},
				{ArgMeta: def.Params[1], Value: info.ContainerId},
			}
			de.ArgsNum = len(de.Args)

			return de, true, nil
		}

		return trace.Event{}, false, nil
	}
}

func deriveDetectHookedSyscall(t *Tracee) deriveFn {
	return func(event trace.Event) (trace.Event, bool, error) {
		syscallsAdresses, err := getEventArgUlongArrVal(&event, "syscalls_addresses")
		if err != nil {
			return trace.Event{}, false, fmt.Errorf("error parsing syscalls_numbers arg: %v", err)
		}
		hookedSyscallData, err := analyzeHookedAddresses(syscallsAdresses, t.config.OSInfo, t.kernelSymbols)
		if err != nil {
			return trace.Event{}, false, fmt.Errorf("error parsing analyzing hooked syscalls adresses arg: %v", err)
		}
		de := event
		de.EventID = int(DetectHookedSyscallsEventID)
		de.EventName = "hooked_syscalls"
		de.ReturnValue = 0
		de.Args = []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "hooked_syscalls", Type: "hookedSyscallData[]"}, Value: hookedSyscallData},
		}
		de.ArgsNum = 1
		return de, true, nil
	}
}

func analyzeHookedAddresses(addresses []uint64, OsConfig *helpers.OSInfo, kernelSymbols *helpers.KernelSymbolTable) ([]bufferdecoder.HookedSyscallData, error) {
	hookedSyscallData := make([]bufferdecoder.HookedSyscallData, 0, 0)
	for idx, syscallsAdress := range addresses {
		InTextSegment, err := kernelSymbols.TextSegmentContains(syscallsAdress)
		if err != nil {
			continue
		}
		if !InTextSegment {
			hookingFunction := parseSymbol(syscallsAdress, kernelSymbols)
			var syscallNumber int32
			if idx > len(syscallsToCheck) {
				return nil, fmt.Errorf("syscall inedx out of the syscalls to check list %v", err)
			}
			syscallNumber = int32(syscallsToCheck[idx])
			event, found := EventsDefinitions[syscallNumber]
			var hookedSyscallName string
			if found {
				hookedSyscallName = event.Name
			} else {
				hookedSyscallName = fmt.Sprint(syscallNumber)
			}
			hookedSyscallData = append(hookedSyscallData, bufferdecoder.HookedSyscallData{hookedSyscallName, hookingFunction.Owner})

		}
	}
	return hookedSyscallData, nil
}

func parseSymbol(address uint64, table *helpers.KernelSymbolTable) *helpers.KernelSymbol {
	hookingFunction, err := table.GetSymbolByAddr(address)
	if err != nil {
		hookingFunction = &helpers.KernelSymbol{}
		hookingFunction.Owner = "hidden"
	}
	hookingFunction.Owner = strings.TrimPrefix(hookingFunction.Owner, "[")
	hookingFunction.Owner = strings.TrimSuffix(hookingFunction.Owner, "]")
	return hookingFunction
}

func deriveHigherLevelEvents(t *Tracee) deriveFn {
	return func(event trace.Event) (trace.Event, bool, error) {
		de := event
		switch event.EventID {
		case int(SchedProcessExecEventID):
			def := EventsDefinitions[ProcessCreationEventID]
			de.EventID = int(ProcessCreationEventID)
			de.EventName = def.Name
			de.ReturnValue = 0
			newArgs := []trace.Argument{}
			for _, arg := range de.Args {
				switch arg.ArgMeta.Name {
				case "cmdpath":
					newArgs = append(newArgs, trace.Argument{ArgMeta: trace.ArgMeta{Type: "const char*", Name: "relative_path"}, Value: arg.Value})
				case "pathname":
					newArgs = append(newArgs, trace.Argument{ArgMeta: trace.ArgMeta{Type: "const char*", Name: "absolute_path"}, Value: arg.Value})
				case "argv":
					newArgs = append(newArgs, trace.Argument{ArgMeta: trace.ArgMeta{Type: "const char**", Name: "arguments"}, Value: arg.Value})
				case "invoked_from_kernel":
					newArgs = append(newArgs, trace.Argument{ArgMeta: trace.ArgMeta{Type: "int", Name: "invoked_from_kernel"}, Value: arg.Value})
				case "ctime":
					newArgs = append(newArgs, trace.Argument{ArgMeta: trace.ArgMeta{Type: "unsigned long", Name: "last_changed"}, Value: arg.Value})
				}
			}
			de.Args = newArgs
			de.ArgsNum = len(newArgs)

		case int(SchedProcessExitEventID):
			def := EventsDefinitions[ProcessTerminationEventID]
			de.EventID = int(ProcessTerminationEventID)
			de.EventName = def.Name
			returnCode, err := getEventArgInt64Val(&event, "exit_code")
			if err != nil {
				return trace.Event{}, false, fmt.Errorf("error parsing return_code arg: %v", err)
			}
			de.Args = []trace.Argument{{ArgMeta: trace.ArgMeta{Type: "long", Name: "exit_code"}, Value: returnCode}}
			de.ArgsNum = 1

		case int(SecurityInodeUnlinkEventID):
			def := EventsDefinitions[FileDeletionEventID]
			de.EventID = int(FileDeletionEventID)
			de.EventName = def.Name
			path, err := getEventArgStringVal(&event, "pathname")
			if err != nil {
				return trace.Event{}, false, fmt.Errorf("error parsing pathname arg: %v", err)
			}
			de.Args = []trace.Argument{{ArgMeta: trace.ArgMeta{Type: "const char*", Name: "absolute_path"}, Value: path}}
			de.ArgsNum = 1
		}

		return de, true, nil
	}
}
