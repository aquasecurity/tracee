package ebpf

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// initDerivationTable initializes tracee's events.DerivationTable.
// we declare for each Event (represented through it's ID) to which other
// events it can be derived and the corresponding function to derive into that Event.
func (t *Tracee) initDerivationTable() error {
	// sanity check for containers dependency
	if t.containers == nil {
		return fmt.Errorf("nil tracee containers")
	}

	t.eventDerivations = events.DerivationTable{
		events.CgroupMkdir: {
			events.ContainerCreate: {
				Enabled:  t.events[events.ContainerCreate].emit,
				Function: deriveContainerCreate(t.containers),
			},
		},
		events.CgroupRmdir: {
			events.ContainerRemove: {
				Enabled:  t.events[events.ContainerRemove].emit,
				Function: deriveContainerRemoved(t.containers),
			},
		},
		events.PrintSyscallTable: {
			events.HookedSyscalls: {
				Enabled:  t.events[events.PrintSyscallTable].emit,
				Function: deriveDetectHookedSyscall(t.kernelSymbols),
			},
		},
		events.DnsRequest: {
			events.NetPacket: {
				Enabled:  t.events[events.NetPacket].emit,
				Function: deriveNetPacket(),
			},
		},
		events.DnsResponse: {
			events.NetPacket: {
				Enabled:  t.events[events.NetPacket].emit,
				Function: deriveNetPacket(),
			},
		},
		events.PrintNetSeqOps: {
			events.HookedSeqOps: {
				Enabled:  t.events[events.HookedSeqOps].emit,
				Function: deriveHookedSeqOps(t.kernelSymbols),
			},
		},
	}

	return nil
}

// deriveEvents is the derivation pipeline stage
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
				derivatives, errors := events.Derive(*event, t.eventDerivations)

				for _, err := range errors {
					t.handleError(err)
				}

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
* The derivation map is then built with the returned events.DeriveFunction functions, which is used in deriveEvents
 */

// deriveContainerCreate receives a containers as a closure argument to track it's containers.
// If it receives a cgroup_mkdir event, it can derive a container_create event from it.
func deriveContainerCreate(containers *containers.Containers) events.DeriveFunction {
	return func(event trace.Event) (trace.Event, bool, error) {
		cgroupId, err := getEventArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return trace.Event{}, false, err
		}

		def := events.Definitions.Get(events.ContainerCreate)
		if info := containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			de := event
			de.EventID = int(events.ContainerCreate)
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

			return de, true, nil
		}

		return trace.Event{}, false, nil
	}
}

// deriveContainerRemoved receives a containers.Containers object as a closure argument to track it's containers.
// If it receives a cgroup_rmdir event, it can derive a container_remove event from it.
func deriveContainerRemoved(containers *containers.Containers) events.DeriveFunction {
	return func(event trace.Event) (trace.Event, bool, error) {
		cgroupId, err := getEventArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return trace.Event{}, false, err
		}

		def := events.Definitions.Get(events.ContainerRemove)
		if info := containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			de := event
			de.EventID = int(events.ContainerRemove)
			de.EventName = def.Name
			de.ReturnValue = 0
			de.StackAddresses = make([]uint64, 1)
			de.Args = []trace.Argument{
				{ArgMeta: def.Params[0], Value: info.Runtime.String()},
				{ArgMeta: def.Params[1], Value: info.Container.ContainerId},
			}
			de.ArgsNum = len(de.Args)

			return de, true, nil
		}

		return trace.Event{}, false, nil
	}
}

func deriveDetectHookedSyscall(kernelSymbols *helpers.KernelSymbolTable) events.DeriveFunction {
	return func(event trace.Event) (trace.Event, bool, error) {
		syscallAddresses, err := getEventArgUlongArrVal(&event, "syscalls_addresses")
		if err != nil {
			return trace.Event{}, false, fmt.Errorf("error parsing syscalls_numbers arg: %v", err)
		}
		hookedSyscall, err := analyzeHookedAddresses(syscallAddresses, kernelSymbols)
		if err != nil {
			return trace.Event{}, false, fmt.Errorf("error parsing analyzing hooked syscalls addresses arg: %v", err)
		}
		de := event
		de.EventID = int(events.HookedSyscalls)
		de.EventName = "hooked_syscalls"
		de.ReturnValue = 0
		de.Args = []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "hooked_syscalls", Type: "[]trace.HookedSymbolData"}, Value: hookedSyscall},
		}
		de.ArgsNum = 1
		return de, true, nil
	}
}

// deriveNetPacket derives net_packet from net events with 'metadata' arg
func deriveNetPacket() events.DeriveFunction {
	return func(event trace.Event) (trace.Event, bool, error) {
		metadataArg := events.GetArg(&event, "metadata")
		if metadataArg == nil {
			return trace.Event{}, false, fmt.Errorf("couldn't find argument name metadata in event %s", event.EventName)
		}

		def := events.Definitions.Get(events.NetPacket)
		de := event
		de.EventID = int(events.NetPacket)
		de.EventName = def.Name
		de.ReturnValue = 0
		de.Args = []trace.Argument{
			*metadataArg,
		}
		de.ArgsNum = 1
		return de, true, nil
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
			syscallsToCheck := events.SyscallsToCheck()
			hookingFunction := parseSymbol(syscallsAddress, kernelSymbols)
			if idx > len(syscallsToCheck) {
				return nil, fmt.Errorf("syscall inedx out of the syscalls to check list %v", err)
			}
			syscallNumber := syscallsToCheck[idx]
			event, found := events.Definitions.GetSafe(syscallNumber)
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

func deriveHookedSeqOps(kernelSymbols *helpers.KernelSymbolTable) events.DeriveFunction {
	return func(event trace.Event) (trace.Event, bool, error) {
		seqOpsArr, err := getEventArgUlongArrVal(&event, "net_seq_ops")
		if err != nil || len(seqOpsArr) < 1 {
			return trace.Event{}, false, err
		}
		seqOpsName := parseSymbol(seqOpsArr[0], kernelSymbols).Name
		hookedSeqOps := make([]trace.HookedSymbolData, 0)
		for _, addr := range seqOpsArr[1:] {
			inTextSegment, err := kernelSymbols.TextSegmentContains(addr)
			if err != nil {
				continue
			}
			if !inTextSegment {
				hookingFunction := parseSymbol(addr, kernelSymbols)
				hookedSeqOps = append(hookedSeqOps, trace.HookedSymbolData{SymbolName: hookingFunction.Name, ModuleOwner: hookingFunction.Owner})
			}
		}
		def := events.Definitions.Get(events.HookedSeqOps)
		de := event
		de.EventID = int(events.HookedSeqOps)
		de.EventName = "hooked_seq_ops"
		de.ReturnValue = 0
		de.StackAddresses = make([]uint64, 1)
		de.Args = []trace.Argument{
			{ArgMeta: def.Params[0], Value: seqOpsName},
			{ArgMeta: def.Params[1], Value: hookedSeqOps},
		}
		de.ArgsNum = 1
		return de, true, nil

	}

}
