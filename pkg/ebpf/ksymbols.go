package ebpf

import (
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// TODO: Just like recent change in `KernelSymbolTable`, in kernel_symbols.go,
// this needs to be changed somehow. Symbols might be duplicated, so might be
// the addresses (https://github.com/aquasecurity/tracee/issues/3798).

var maxKsymNameLen = 64 // Most match the constant in the bpf code
var globalSymbolOwner = "system"

func (t *Tracee) UpdateKallsyms() error {
	// NOTE: Make sure to refresh the kernel symbols table before updating the eBPF map.

	// Find the eBPF map.
	bpfKsymsMap, err := t.bpfModule.GetMap("ksymbols_map")
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Wrap long method names.
	evtDefSymDeps := func(id events.ID) []events.KSymbol {
		depsNode, _ := t.eventsDependencies.GetEvent(id)
		deps := depsNode.GetDependencies()
		return deps.GetKSymbols()
	}

	// Get the symbols all events being traced require (t.eventsState already
	// includes dependent events, no need to recurse again).

	var allReqSymbols []string

	for _, evtID := range t.policyManager.EventsSelected() {
		for _, symDep := range evtDefSymDeps(evtID) {
			allReqSymbols = append(allReqSymbols, symDep.GetSymbolName())
		}
	}

	// For every ksymbol required by tracee ...
	for _, required := range allReqSymbols {
		// ... get the symbol address from the kallsyms file ...
		symbol, err := t.getKernelSymbols().GetSymbolByOwnerAndName(globalSymbolOwner, required)
		if err != nil {
			logger.Debugw("failed to get symbol", "symbol", required, "error", err)
			continue
		}

		// ... and update the eBPF map with the symbol address.
		for _, sym := range symbol {
			key := make([]byte, maxKsymNameLen)
			copy(key, sym.Name)
			addr := sym.Address

			// Update the eBPF map with the symbol address.
			err := bpfKsymsMap.Update(
				unsafe.Pointer(&key[0]),
				unsafe.Pointer(&addr),
			)
			if err != nil {
				return errfmt.WrapError(err)
			}
		} // will overwrite the previous value (check TODO)
	}

	return nil
}
