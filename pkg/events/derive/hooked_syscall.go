package derive

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/symbols"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	maxSysCallTableSize = 500
)

var (
	reportedHookedSyscalls *lru.Cache[int32, uint64]
	initOnce               sync.Once
	initErr                error
)

// InitHookedSyscall initialize lru (thread-safe, only runs once)
func InitHookedSyscall() error {
	initOnce.Do(func() {
		reportedHookedSyscalls, initErr = lru.New[int32, uint64](maxSysCallTableSize)
	})
	return initErr
}

// resetHookedSyscallForTesting resets the cache and initialization state for testing purposes only
func resetHookedSyscallForTesting() error {
	// No mutex is needed since the tests run sequentially (critical assumption)
	initOnce = sync.Once{}
	reportedHookedSyscalls = nil
	initErr = nil

	return InitHookedSyscall()
}

func DetectHookedSyscall(kernelSymbols *symbols.KernelSymbolTable) DeriveFunction {
	return deriveMultipleEvents(events.HookedSyscall, deriveDetectHookedSyscallArgs(kernelSymbols))
}

func deriveDetectHookedSyscallArgs(kernelSymbols *symbols.KernelSymbolTable) multiDeriveArgsFunction {
	return func(event *trace.Event) ([][]interface{}, []error) {
		syscallId, err := parse.ArgVal[int32](event.Args, "syscall_id")
		if err != nil {
			return nil, []error{errfmt.Errorf("error parsing syscall_id arg: %v", err)}
		}

		address, err := parse.ArgVal[uint64](event.Args, "syscall_address")
		if err != nil {
			return nil, []error{errfmt.Errorf("error parsing syscall_address arg: %v", err)}
		}

		// Cache hit: don't report the same syscall_id and address again
		alreadyReportedAddress, found := reportedHookedSyscalls.Get(syscallId)
		if found && alreadyReportedAddress == address {
			return nil, nil
		}

		reportedHookedSyscalls.Add(syscallId, address) // Upsert: if the key already exists, the value is updated

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
