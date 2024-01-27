package global

import (
	"strings"
	"sync"
	"unsafe"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// TODO: Just like recent change in `KernelSymbolTable`, in kernel_symbols.go,
// this needs to be changed somehow. Symbols might be duplicated, so might be
// the addresses (https://github.com/aquasecurity/tracee/issues/3798).

var maxKsymNameLen = 64 // Most match the constant in the bpf code
var globalSymbolOwner = "system"

//
// Functions
//

var updateKallsymsLock *sync.Mutex

// UpdateKallsyms updates the eBPF map with the addresses of the kernel symbols required
// by the events being traced. The events must already be in the `states.All()` map when
// calling this method.
func UpdateKallsyms() error {
	// NOTE: Make sure to refresh the kernel symbols table before updating the eBPF map.

	// Single goroutine at a time.
	if updateKallsymsLock == nil {
		updateKallsymsLock = &sync.Mutex{}
	}
	updateKallsymsLock.Lock()
	defer updateKallsymsLock.Unlock()

	// Find the eBPF map.
	bpfKsymsMap, err := extensions.Modules.Get("core").GetMap("ksymbols_map")
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Wrap long method names.
	evtDefSymDeps := func(id events.ID) []events.KSymbol {
		return events.Core.GetDefinitionByID(id).GetDependencies().GetKSymbols()
	}

	// Get the symbols all events being traced require (t.eventsState already
	// includes dependent events, no need to recurse again).

	var allReqSymbols []string

	for _, id := range extensions.States.GetEventIDs("core") {
		evtID := events.ID(id)
		for _, symDep := range evtDefSymDeps(evtID) {
			allReqSymbols = append(allReqSymbols, symDep.GetSymbolName())
		}
	}

	// For every ksymbol required by tracee ...
	for _, required := range allReqSymbols {
		// ... get the symbol address from the kallsyms file ...
		symbol, err := KSymbols.GetSymbolByOwnerAndName(globalSymbolOwner, required)
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

// ParseKSymbol returns the kernel symbol that corresponds to the given address.
func ParseKSymbol(address uint64) helpers.KernelSymbol {
	var hookingFunction helpers.KernelSymbol

	symbols, err := KSymbols.GetSymbolByAddr(address)
	if err != nil {
		hookingFunction = helpers.KernelSymbol{}
		hookingFunction.Owner = "hidden"
	} else {
		hookingFunction = symbols[0]
	}

	hookingFunction.Owner = strings.TrimPrefix(hookingFunction.Owner, "[")
	hookingFunction.Owner = strings.TrimSuffix(hookingFunction.Owner, "]")

	return hookingFunction
}

var validateKsymsLock *sync.Mutex

// ValidateKsymsDepsAndCancelUnavailable checks if all kernel symbols required by the
// events being traced are available in the kernel symbols table. If not, it cancels the
// events that have missing kernel symbol dependencies.
func ValidateKsymsDepsAndCancelUnavailable() {
	// Single goroutine at a time.
	if validateKsymsLock == nil {
		validateKsymsLock = &sync.Mutex{}
	}
	validateKsymsLock.Lock()
	defer validateKsymsLock.Unlock()

	// Cancel events that have missing kernel symbol dependencies.
	for eventIDToCancel, missingDepSyms := range GetUnavailableSymbolPerEventID() {
		// Cancel the event.

		eventNameToCancel := events.Core.GetDefinitionByID(eventIDToCancel).GetName()
		logger.Debugw(
			"Event canceled because of missing kernel symbol dependency",
			"missing symbols", missingDepSyms, "event", eventNameToCancel,
		)
		extensions.States.Delete("core", int(eventIDToCancel))

		// Cancel its dependent events.

		depsToCancel := make(map[events.ID]string)

		for _, id := range extensions.States.GetEventIDs("core") {
			evtID := events.ID(id)
			depsIDs := events.Core.GetDefinitionByID(evtID).GetDependencies().GetIDs()
			for _, depID := range depsIDs {
				if depID == eventIDToCancel {
					depsToCancel[evtID] = eventNameToCancel
				}
			}
		}
		for eventID, depEventName := range depsToCancel {
			logger.Debugw(
				"Event canceled because it depends on an previously canceled event",
				"event", events.Core.GetDefinitionByID(eventID).GetName(),
				"dependency", depEventName,
			)
			extensions.States.Delete("core", int(eventID))
		}
	}
}

// GetUnavailableSymbolPerEventID returns a map of event IDs to the list of kernel symbols
// that are required by the event but are not available in the kernel symbols table.
func GetUnavailableSymbolPerEventID() map[events.ID][]string {
	unSymbols := map[events.ID][]string{}

	evtDefSymDeps := func(id events.ID) []events.KSymbol {
		return events.Core.GetDefinitionByID(id).GetDependencies().GetKSymbols()
	}

	// For all events being traced and for each symbol dependency of the event ...
	for _, id := range extensions.States.GetEventIDs("core") {
		evtID := events.ID(id)
		for _, symDep := range evtDefSymDeps(evtID) {
			symbols, err := KSymbols.GetSymbolByName(symDep.GetSymbolName())
			if err != nil {
				unSymbols[evtID] = append(unSymbols[evtID], symDep.GetSymbolName())
				continue
			}
			for _, symbol := range symbols {
				if symbol.Address == 0 { // symbol address unavailable
					unSymbols[evtID] = append(unSymbols[evtID], symDep.GetSymbolName())
				}
			}
		}
	}

	return unSymbols
}
