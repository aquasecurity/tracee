package ebpf

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/ebpf/events/derived"
	"github.com/aquasecurity/tracee/pkg/events/parsing"
	"github.com/aquasecurity/tracee/pkg/utils/shared_objects"
	"github.com/aquasecurity/tracee/types/trace"
)

// Initialize the eventDerivations map.
// Here we declare for each Event (represented through it's ID)
// to which other Events it can be derived and the corresponding function to derive into that Event.
func (t *Tracee) initEventDerivationMap() error {
	soSymbolsCollisionsDeriveFn := deriveSharedObjectLoadedSymbolsCollision(t)
	t.eventDerivations = map[int32]map[int32]derived.DeriveFn{
		CgroupMkdirEventID: {
			ContainerCreateEventID: deriveContainerCreate(t),
		},
		CgroupRmdirEventID: {
			ContainerRemoveEventID: deriveContainerRemoved(t),
		},
		PrintSyscallTableEventID: {
			HookedSyscallsEventID: deriveDetectHookedSyscall(t),
		},
		DnsRequest: {
			NetPacket: deriveNetPacket(),
		},
		DnsResponse: {
			NetPacket: deriveNetPacket(),
		},
		PrintNetSeqOpsEventID: {
			HookedSeqOpsEventID: deriveHookedSeqOps(t),
		},
		SharedObjectLoadedEventID: {
			ImportSymbolsCollisionEventID: soSymbolsCollisionsDeriveFn,
			SOExportWatchedSymbolEventID:  derivedSharedObjectExportWatchedSymbols(t),
		},
		SchedProcessExecEventID: {
			ImportSymbolsCollisionEventID: soSymbolsCollisionsDeriveFn,
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
			derivatives = append(derivatives, derivative...)
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
* Tracee builds its derivation map from these functions and injects itself as an argument to the closures
* The derivation map is then built with the returned DeriveFn functions, which is used in deriveEvents
 */

//Receives a tracee object as a closure argument to track it's containers
//If it receives a cgroup_mkdir event, it can derive a container_create event from it
func deriveContainerCreate(t *Tracee) derived.DeriveFn {
	return func(event trace.Event) ([]trace.Event, bool, error) {
		cgroupId, err := parsing.GetEventArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return []trace.Event{}, false, err
		}

		def := EventsDefinitions[ContainerCreateEventID]
		if info := t.containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			de := event
			de.EventID = int(ContainerCreateEventID)
			de.EventName = def.Name
			de.ReturnValue = 0
			de.StackAddresses = make([]uint64, 1)
			de.Args = []trace.Argument{
				{ArgMeta: def.Params[0], Value: info.Runtime.String()},
				{ArgMeta: def.Params[1], Value: info.Container.ContainerId},
				{ArgMeta: def.Params[2], Value: info.Ctime.UnixNano()},
				{ArgMeta: def.Params[3], Value: info.Container.Image},
				{ArgMeta: def.Params[4], Value: info.Container.Name},
				{ArgMeta: def.Params[5], Value: info.Container.Pod.Name},
				{ArgMeta: def.Params[6], Value: info.Container.Pod.Namespace},
				{ArgMeta: def.Params[7], Value: info.Container.Pod.UID},
			}
			de.ArgsNum = len(de.Args)

			return []trace.Event{de}, true, nil
		}

		return []trace.Event{}, false, nil
	}
}

//Receives a tracee object as a closure argument to track it's containers
//If it receives a cgroup_rmdir event, it can derive a container_remove event from it
func deriveContainerRemoved(t *Tracee) derived.DeriveFn {
	return func(event trace.Event) ([]trace.Event, bool, error) {
		cgroupId, err := parsing.GetEventArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return []trace.Event{}, false, err
		}

		def := EventsDefinitions[ContainerRemoveEventID]
		if info := t.containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			de := event
			de.EventID = int(ContainerRemoveEventID)
			de.EventName = def.Name
			de.ReturnValue = 0
			de.StackAddresses = make([]uint64, 1)
			de.Args = []trace.Argument{
				{ArgMeta: def.Params[0], Value: info.Runtime.String()},
				{ArgMeta: def.Params[1], Value: info.Container.ContainerId},
			}
			de.ArgsNum = len(de.Args)

			return []trace.Event{de}, true, nil
		}

		return []trace.Event{}, false, nil
	}
}

func deriveDetectHookedSyscall(t *Tracee) derived.DeriveFn {
	return func(event trace.Event) ([]trace.Event, bool, error) {
		syscallAddresses, err := parsing.GetEventArgUlongArrVal(&event, "syscalls_addresses")
		if err != nil {
			return []trace.Event{}, false, fmt.Errorf("error parsing syscalls_numbers arg: %v", err)
		}
		hookedSyscall, err := analyzeHookedAddresses(syscallAddresses, t.kernelSymbols)
		if err != nil {
			return []trace.Event{}, false, fmt.Errorf("error parsing analyzing hooked syscalls addresses arg: %v", err)
		}
		de := event
		de.EventID = int(HookedSyscallsEventID)
		de.EventName = "hooked_syscalls"
		de.ReturnValue = 0
		de.Args = []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "hooked_syscalls", Type: "[]trace.HookedSymbolData"}, Value: hookedSyscall},
		}
		de.ArgsNum = 1
		return []trace.Event{de}, true, nil
	}
}

// deriveNetPacket derives net_packet from net events with 'metadata' arg
func deriveNetPacket() derived.DeriveFn {
	return func(event trace.Event) ([]trace.Event, bool, error) {
		metadataArg := getEventArg(&event, "metadata")
		if metadataArg == nil {
			return nil, false, fmt.Errorf("couldn't find argument name metadata in event %s", event.EventName)
		}

		def := EventsDefinitions[NetPacket]
		de := event
		de.EventID = int(NetPacket)
		de.EventName = def.Name
		de.ReturnValue = 0
		de.Args = []trace.Argument{
			*metadataArg,
		}
		de.ArgsNum = 1
		return []trace.Event{de}, true, nil
	}
}

func analyzeHookedAddresses(addresses []uint64, kernelSymbols *helpers.KernelSymbolTable) ([]trace.HookedSymbolData, error) {
	hookedSyscalls := make([]trace.HookedSymbolData, 0)
	for idx, syscallsAddress := range addresses {
		InTextSegment, err := kernelSymbols.TextSegmentContains(syscallsAddress)
		if err != nil {
			continue
		}
		if !InTextSegment {
			hookingFunction := parseSymbol(syscallsAddress, kernelSymbols)
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
			hookedSyscalls = append(hookedSyscalls, trace.HookedSymbolData{SymbolName: hookedSyscallName, ModuleOwner: hookingFunction.Owner})

		}
	}
	return hookedSyscalls, nil
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

var seq_ops_functions = [4]string{
	"seq_show",
	"seq_open",
	"seq_close",
	"seq_next",
}

func deriveHookedSeqOps(t *Tracee) derived.DeriveFn {
	return func(event trace.Event) ([]trace.Event, bool, error) {
		seqOpsArr, err := parsing.GetEventArgUlongArrVal(&event, "net_seq_ops")
		if err != nil || len(seqOpsArr) < 1 {
			return []trace.Event{}, false, err
		}
		seqOpsName := parseSymbol(seqOpsArr[0], t.kernelSymbols).Name
		hookedSeqOps := make([]trace.HookedSymbolData, 0)
		for _, addr := range seqOpsArr[1:] {
			inTextSegment, err := t.kernelSymbols.TextSegmentContains(addr)
			if err != nil {
				continue
			}
			if !inTextSegment {
				hookingFunction := parseSymbol(addr, t.kernelSymbols)
				hookedSeqOps = append(hookedSeqOps, trace.HookedSymbolData{SymbolName: hookingFunction.Name, ModuleOwner: hookingFunction.Owner})
			}
		}
		def := EventsDefinitions[HookedSeqOpsEventID]
		de := event
		de.EventID = int(HookedSeqOpsEventID)
		de.EventName = "hooked_seq_ops"
		de.ReturnValue = 0
		de.StackAddresses = make([]uint64, 1)
		de.Args = []trace.Argument{
			{ArgMeta: def.Params[0], Value: seqOpsName},
			{ArgMeta: def.Params[1], Value: hookedSeqOps},
		}
		de.ArgsNum = 1
		return []trace.Event{de}, true, nil

	}

}

func deriveSharedObjectLoadedSymbolsCollision(t *Tracee) derived.DeriveFn {
	def := EventsDefinitions[ImportSymbolsCollisionEventID]
	defSkel := derived.EventSkeleton{Name: def.Name,
		ID:     int(ImportSymbolsCollisionEventID),
		Params: def.Params}
	pathResolver := containers.InitContainersPathReslover(&t.pidsInMntns)
	soLoader := shared_objects.InitContainersSOSymbolsLoader(&pathResolver)
	soColGen := derived.InitSOCollisionsEventGenerator(defSkel, &soLoader)

	return derived.GenerateDerivedFn(&soColGen)
}

func derivedSharedObjectExportWatchedSymbols(t *Tracee) derived.DeriveFn {
	def := EventsDefinitions[SOExportWatchedSymbolEventID]
	defSkel := derived.EventSkeleton{Name: def.Name,
		ID:     int(SOExportWatchedSymbolEventID),
		Params: def.Params,
	}
	pathResolver := containers.InitContainersPathReslover(&t.pidsInMntns)
	soLoader := shared_objects.InitContainersSOSymbolsLoader(&pathResolver)
	soExSymGen := derived.InitSOExportWatchedSymbolsEventGenerator(
		defSkel,
		&soLoader,
		t.config.Filter.SOExportedSymbols.Equal,
		t.config.Filter.LibrariesPrefixWhitelist.Equal)

	return derived.GenerateDerivedFn(&soExSymGen)
}
