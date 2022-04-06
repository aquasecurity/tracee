package ebpf

import (
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
		FetchProcFopsEventID: {
			DetectHookedProcFopsEventID: deriveDetectHookedProcFops(t),
		},
	}

	return nil
}

const (
	StructFopsPointer int = iota + 1
	IterateShared
)

// deriveEvent takes a trace.Event and checks if it can derive additional events from it
// as defined by tracee's eventDerivations map.
// The map is initialized in the above function
func (t *Tracee) deriveEvent(event trace.Event) []trace.Event {
	derivatives := []trace.Event{}
	deriveFns := t.eventDerivations[int32(event.EventID)]
	for id, deriveFn := range deriveFns {
		// Don't derive events which were not requested by the user
		if !t.eventsToTrace[id] {
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

func analyzeHookedAddresses(addresses []uint64, OsConfig *helpers.OSInfo, kernelSymbols *helpers.KernelSymbolTable) ([]bufferdecoder.HookedSymbolData, error) {
	hookedSyscallData := make([]bufferdecoder.HookedSymbolData, 0, 0)
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
			hookedSyscallData = append(hookedSyscallData, bufferdecoder.HookedSymbolData{hookedSyscallName, hookingFunction.Owner})

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

func deriveDetectHookedProcFops(t *Tracee) deriveFn {
	return func(event trace.Event) (trace.Event, bool, error) {
		fopsAddresses, err := getEventArgUlongArrVal(&event, "fops_address")
		if err != nil {
			return trace.Event{}, false, err
		}
		hookedFops := make([]bufferdecoder.HookedSymbolData, 0, 0)
		for idx, addr := range fopsAddresses {
			inTextSeg, err := t.kernelSymbols.TextSegmentContains(addr)
			if err != nil {
				return trace.Event{}, false, fmt.Errorf("error checking kernel address: %v", err)
			}
			if !inTextSeg {
				hookingFunction, err := t.kernelSymbols.GetSymbolByAddr(addr)
				if hookingFunction.Owner == "system" && err == nil {
					continue
				}
				if err != nil {
					hookingFunction.Owner = "hidden"
				} else {
					hookingFunction.Owner = strings.TrimPrefix(hookingFunction.Owner, "[")
					hookingFunction.Owner = strings.TrimSuffix(hookingFunction.Owner, "]")
				}
				functionName := "unknown"
				switch idx + 1 {
				case StructFopsPointer:
					functionName = "struct file_operations pointer"
				case IterateShared:
					functionName = "iterate_shared"
				}
				hookedFops = append(hookedFops, bufferdecoder.HookedSymbolData{functionName, hookingFunction.Owner})
			}
		}
		def := EventsDefinitions[DetectHookedProcFopsEventID]
		de := event
		de.EventID = int(DetectHookedProcFopsEventID)
		de.EventName = "detect_hooked_proc_fops"
		de.ReturnValue = 0
		de.Args = []trace.Argument{
			{ArgMeta: def.Params[0], Value: hookedFops},
		}
		de.ArgsNum = 1

		return de, true, nil
	}

}
