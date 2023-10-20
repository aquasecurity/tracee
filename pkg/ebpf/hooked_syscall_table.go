package ebpf

import (
	gocontext "context"
	"runtime"
	"strings"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

var expectedSyscallTableInit = false

// hookedSyscallTableRoutine the main routine that checks if there's a hooked syscall in the syscall table.
// It runs on tracee's startup and from time to time.
func (t *Tracee) hookedSyscallTableRoutine(ctx gocontext.Context) {
	logger.Debugw("Starting hookedSyscallTable goroutine")
	defer logger.Debugw("Stopped hookedSyscallTable goroutine")

	if t.eventsState[events.HookedSyscall].Emit == 0 {
		return
	}

	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		logger.Debugw("hooked syscall table: unsupported architecture")
		return
	}

	err := derive.InitHookedSyscall()
	if err != nil {
		logger.Errorw("Error occurred InitHookedSyscall: " + err.Error())
		return
	}

	expectedSyscallTableMap, err := t.bpfModule.GetMap("expected_sys_call_table")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	err = capabilities.GetInstance().EBPF(
		func() error {
			return t.populateExpectedSyscallTableArray(expectedSyscallTableMap)
		},
	)
	if err != nil {
		logger.Errorw("Error populating expected syscall table array: " + err.Error())
		return
	}

	expectedSyscallTableInit = true

	t.triggerSyscallTableIntegrityCheckCall() // First time run immediately

	// Run from time to time
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(utils.GenerateRandomDuration(10, 300)):
			t.triggerSyscallTableIntegrityCheckCall()
		}
	}
}

// populateExpectedSyscallTableArray fills the expected values of the syscall table
func (t *Tracee) populateExpectedSyscallTableArray(tableMap *bpf.BPFMap) error {
	// Get address to the function that defines the not implemented sys call
	niSyscallSymbol, err := t.kernelSymbols.GetSymbolByName("system", events.SyscallPrefix+"ni_syscall")
	if err != nil {
		return err
	}
	niSyscallAddress := niSyscallSymbol.Address

	for i, syscallName := range events.SyscallSymbolNames {
		var index = uint32(i)

		if strings.HasPrefix(syscallName, events.SyscallNotImplemented) {
			err = tableMap.Update(unsafe.Pointer(&index), unsafe.Pointer(&niSyscallAddress))
			if err != nil {
				return err
			}
			continue
		}

		kernelSymbol, err := t.kernelSymbols.GetSymbolByName("system", events.SyscallPrefix+syscallName)
		if err != nil {
			return err
		}

		var expectedAddress = kernelSymbol.Address
		err = tableMap.Update(unsafe.Pointer(&index), unsafe.Pointer(&expectedAddress))
		if err != nil {
			return err
		}
	}

	return nil
}

//go:noinline
func (t *Tracee) triggerSyscallTableIntegrityCheckCall() {
}
