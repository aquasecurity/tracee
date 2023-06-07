package derive

import (
	"fmt"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

var SyscallsToCheck = make([]string, 0)
var MaxSupportedSyscallID = events.IoPgetevents // Was the last syscall introduced in the minimum version supported 4.18

func DetectHookedSyscall(kernelSymbols helpers.KernelSymbolTable) DeriveFunction {
	return deriveSingleEvent(events.HookedSyscalls, deriveDetectHookedSyscallArgs(kernelSymbols))
}

func deriveDetectHookedSyscallArgs(kernelSymbols helpers.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		syscallAddresses, err := parse.ArgVal[[]uint64](event.Args, "syscalls_addresses")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscalls_numbers arg: %v", err)
		}
		hookedSyscall, err := analyzeHookedAddresses(syscallAddresses, kernelSymbols)
		if err != nil {
			return nil, errfmt.Errorf("error parsing analyzing hooked syscalls addresses arg: %v", err)
		}
		return []interface{}{SyscallsToCheck, hookedSyscall}, nil
	}
}

func analyzeHookedAddresses(addresses []uint64, kernelSymbols helpers.KernelSymbolTable) ([]trace.HookedSymbolData, error) {
	hookedSyscalls := make([]trace.HookedSymbolData, 0)

	for _, syscall := range SyscallsToCheck {
		eventNamesToIDs := events.Definitions.NamesToIDs()
		syscallID, ok := eventNamesToIDs[syscall]
		if !ok {
			return hookedSyscalls, errfmt.Errorf("%s - no such syscall", syscall)
		}
		syscallAddress := addresses[syscallID]
		// syscall pointer is null or in kernel bounds
		if syscallAddress == 0 {
			continue
		}
		if inText, err := kernelSymbols.TextSegmentContains(syscallAddress); err != nil || inText {
			continue
		}

		hookingFunction := utils.ParseSymbol(syscallAddress, kernelSymbols)
		event, found := events.Definitions.GetSafe(syscallID)
		var hookedSyscallName string
		if found {
			hookedSyscallName = event.Name
		} else {
			hookedSyscallName = fmt.Sprint(syscallID)
		}
		hookedSyscalls = append(hookedSyscalls, trace.HookedSymbolData{SymbolName: hookedSyscallName, ModuleOwner: hookingFunction.Owner})
	}
	return hookedSyscalls, nil
}
