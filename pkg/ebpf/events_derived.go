package ebpf

import (
	"fmt"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/types/trace"
	"strings"
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
	return func(event trace.Event)  (trace.Event, bool, error) {
		syscallsAdresses, err := getEventArgUlongArrVal(&event, "syscalls_addresses")
		if err != nil {
			return trace.Event{}, false, fmt.Errorf("error parsing syscalls_numbers arg: %v", err)
		}
		hookedSyscallData := t.ParseHookedAddresses(syscallsAdresses)
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

func (t *Tracee) ParseHookedAddresses(addresses []uint64) []bufferdecoder.HookedSyscallData {
	hookedSyscallData := make([]bufferdecoder.HookedSyscallData, 0, 0)
	for idx, syscallsAdress := range addresses {
		InTextSegment, err := t.kernelSymbols.TextSegmentContains(syscallsAdress)
		if err != nil {
			continue
		}
		if !InTextSegment {
			hookingFunction := t.ParseSymbol(syscallsAdress)
			arch := t.config.OsConfig.GetOSReleaseFieldValue(helpers.OS_ARCH)
			var syscallNumber int32
			if strings.Compare(arch, "x86_64") == 0 {
				if idx > len(syscallsToCheckX86) {
					continue
				}
				syscallNumber = int32(syscallsToCheckX86[idx])
			} else {
				if idx > len(syscallsToCheckArm) {
					continue
				}
				syscallNumber = int32(syscallsToCheckArm[idx])
			}
			event, found := EventsDefinitions[syscallNumber]
			var hookedSyscall bufferdecoder.HookedSyscallData
			if found {
				hookedSyscall = bufferdecoder.HookedSyscallData{event.Name, hookingFunction.Owner}
			} else {
				hookedSyscall = bufferdecoder.HookedSyscallData{fmt.Sprint(syscallNumber), hookingFunction.Owner}
			}
			hookedSyscallData = append(hookedSyscallData, hookedSyscall)
		}
	}
	return hookedSyscallData
}

func (t *Tracee) ParseSymbol(address uint64) *helpers.KernelSymbol {
	hookingFunction, err := t.kernelSymbols.GetSymbolByAddr(address)
	if err != nil {
		hookingFunction = &helpers.KernelSymbol{}
		hookingFunction.Owner = "hidden"
	}
	hookingFunction.Owner = strings.TrimPrefix(hookingFunction.Owner, "[")
	hookingFunction.Owner = strings.TrimSuffix(hookingFunction.Owner, "]")
	return hookingFunction
}
