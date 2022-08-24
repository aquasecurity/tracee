package derive

import (
	"fmt"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

func DetectHookedSyscall(kernelSymbols *helpers.KernelSymbolTable) deriveFunction {
	return deriveSingleEvent(events.HookedSyscalls, deriveDetectHookedSyscallArgs(kernelSymbols))
}

func deriveDetectHookedSyscallArgs(kernelSymbols *helpers.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		syscallAddresses, err := parse.ArgUlongArrVal(&event, "syscalls_addresses")
		if err != nil {
			return nil, fmt.Errorf("error parsing syscalls_numbers arg: %v", err)
		}
		hookedSyscall, err := analyzeHookedAddresses(syscallAddresses, kernelSymbols)
		if err != nil {
			return nil, fmt.Errorf("error parsing analyzing hooked syscalls addresses arg: %v", err)
		}
		return []interface{}{hookedSyscall}, nil
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
			hookingFunction := utils.ParseSymbol(syscallsAddress, kernelSymbols)
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
