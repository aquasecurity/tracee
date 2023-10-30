package ebpf

import (
	gocontext "context"
	"runtime"
	"strings"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

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

	if t.eventsState[events.HookedSyscall].Submit == 0 {
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

// isAboveSatisfied is 'above' requirement satisfied
func (t *Tracee) isAboveSatisfied(aboveRequirement string) (bool, error) {
	kerVerCmpAbove, err := t.config.OSInfo.CompareOSBaseKernelRelease(aboveRequirement)
	if err != nil {
		return false, err
	}

	if kerVerCmpAbove == helpers.KernelVersionOlder || kerVerCmpAbove == helpers.KernelVersionEqual { // above requirement is older/equal running kernel (aka satisfies requirement)
		return true, nil
	}

	return false, nil
}

// isBelowSatisfied is 'below' requirement satisfied
func (t *Tracee) isBelowSatisfied(belowRequirement string) (bool, error) {
	kerVerCmpBelow, err := t.config.OSInfo.CompareOSBaseKernelRelease(belowRequirement)
	if err != nil {
		return false, err
	}

	if kerVerCmpBelow == helpers.KernelVersionNewer { // below requirement is newer than running kernel (aka satisfies requirement)
		return true, nil
	}

	return false, nil
}

// getSyscallNameByKerVer searches for a syscall name that satisfies 'above' and 'below' kernel version requirements
// in comparison with the current running kernel.
// 'below' requirement is exclusive, 'above' is inclusive.
// For example, for running kernel 6.2, 'below'==6.2 is NOT a match, whereas 'above'==6.2 is a match.
func (t *Tracee) getSyscallNameByKerVer(restrictions []events.KernelRestrictions) string {
	for _, restriction := range restrictions {
		below := restriction.Below
		above := restriction.Above

		if above == "" && below == "" {
			// no requirements - found a match
			return restriction.Name
		}

		if below != "" {
			// There's a 'below' requirement - check it
			isMatch, err := t.isBelowSatisfied(below)
			if err != nil {
				return ""
			}

			if !isMatch {
				continue
			}

			// 'below' match - is there an 'above' requirement?

			if above == "" { // no above - we found a match
				return restriction.Name
			}

			// Check match with 'above'

			isMatch, err = t.isAboveSatisfied(above)
			if err != nil {
				return ""
			}

			if isMatch {
				// Both requirements pass - found a match
				return restriction.Name
			}
		} else if above != "" {
			// If we're here then we only have 'above' requirement
			isMatch, err := t.isAboveSatisfied(above)
			if err != nil {
				return ""
			}

			if isMatch {
				return restriction.Name
			}
		}
	}
	return "" // no match found - kernel does not support this syscall
}

// populateExpectedSyscallTableArray fills the expected values of the syscall table
func (t *Tracee) populateExpectedSyscallTableArray(tableMap *bpf.BPFMap) error {
	// Get address to the function that defines the not implemented sys call
	niSyscallSymbol, err := t.kernelSymbols.GetSymbolByName("system", events.SyscallPrefix+"ni_syscall")
	if err != nil {
		return err
	}
	niSyscallAddress := niSyscallSymbol.Address

	for i, kernelRestrictionArr := range events.SyscallSymbolNames {
		syscallName := t.getSyscallNameByKerVer(kernelRestrictionArr)
		if syscallName == "" {
			logger.Debugw("hooked_syscall: skipping syscall", "index", i)
			continue
		}
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
			logger.Errorw("hooked_syscall: syscall symbol not found", "id", index)
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
