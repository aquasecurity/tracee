package derive

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	maxSysCallTableSize = 500
)

var (
	reportedHookedSyscalls *lru.Cache[int32, uint64]
)

// InitHookedSyscall initialize lru
func InitHookedSyscall() error {
	var err error
	reportedHookedSyscalls, err = lru.New[int32, uint64](maxSysCallTableSize)
	return err
}

func DetectHookedSyscall(kernelSymbols *environment.KernelSymbolTable) DeriveFunction {
	return deriveMultipleEvents(events.HookedSyscall, deriveDetectHookedSyscallArgs(kernelSymbols))
}

func deriveDetectHookedSyscallArgs(kernelSymbols *environment.KernelSymbolTable) multiDeriveArgsFunction {
	return func(event trace.Event) ([][]interface{}, []error) {
		syscallId, err := parse.ArgVal[int32](event.Args, "syscall_id")
		if err != nil {
			return nil, []error{errfmt.Errorf("error parsing syscall_id arg: %v", err)}
		}

		address, err := parse.ArgVal[uint64](event.Args, "syscall_address")
		if err != nil {
			return nil, []error{errfmt.Errorf("error parsing syscall_address arg: %v", err)}
		}

		alreadyReportedAddress, found := reportedHookedSyscalls.Get(syscallId)
		if found && alreadyReportedAddress == address {
			return nil, nil
		}

		reportedHookedSyscalls.Add(syscallId, address) // Upsert

		syscallName := convertToSyscallName(syscallId)
		hexAddress := fmt.Sprintf("%x", address)

		hookedFuncSymbols, err := kernelSymbols.GetSymbolByAddr(address)
		if err != nil {
			return [][]interface{}{{syscallName, hexAddress, "", ""}}, nil
		}

		events := make([][]interface{}, 0)
		for _, symbol := range hookedFuncSymbols {
			events = append(events, []interface{}{syscallName, hexAddress, symbol.Name, symbol.Owner})
		}

		return events, nil
	}
}

func convertToSyscallName(syscallId int32) string {
	definition, ok := events.CoreEvents[events.ID(syscallId)]
	if !ok {
		return ""
	}
	return definition.GetName()
}
