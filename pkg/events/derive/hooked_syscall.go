package derive

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/global"
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

func DetectHookedSyscall() DeriveFunction {
	return deriveSingleEvent(extensions.HookedSyscall, deriveDetectHookedSyscallArgs())
}

func deriveDetectHookedSyscallArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		syscallId, err := parse.ArgVal[int32](event.Args, "syscall_id")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscall_id arg: %v", err)
		}

		address, err := parse.ArgVal[uint64](event.Args, "syscall_address")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscall_address arg: %v", err)
		}

		alreadyReportedAddress, found := reportedHookedSyscalls.Get(syscallId)
		if found && alreadyReportedAddress == address {
			return nil, nil
		}

		reportedHookedSyscalls.Add(syscallId, address) // Upsert

		hookedFuncName := ""
		hookedOwner := ""
		hookedFuncSymbol, err := global.KSymbols.GetSymbolByAddr(address)
		if err == nil {
			hookedFuncName = hookedFuncSymbol[0].Name
			hookedOwner = hookedFuncSymbol[0].Owner
		}

		syscallName := convertToSyscallName(syscallId)
		hexAddress := fmt.Sprintf("%x", address)

		return []interface{}{syscallName, hexAddress, hookedFuncName, hookedOwner}, nil
	}
}

func convertToSyscallName(syscallId int32) string {
	definition, ok := extensions.CoreEvents[int(syscallId)]
	if !ok {
		return ""
	}
	return definition.GetName()
}
