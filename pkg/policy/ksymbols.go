package policy

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/ksymbols"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// ValidateKallsymsDependencies load all symbols required by events dependencies
// from the kallsyms file to check for missing symbols. If some symbols are
// missing, it will cancel their event with informative error message.
func (ps *Policies) ValidateKallsymsDependencies() {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	depsToCancel := make(map[events.ID]string)

	// Cancel events with unavailable symbols dependencies
	for eventToCancel, missingDepSyms := range getUnavKsymsPerEvtID(ps.evtsStates) {
		eventNameToCancel := events.Core.GetDefinitionByID(eventToCancel).GetName()
		logger.Debugw(
			"Event cancelled because of missing kernel symbol dependency",
			"missing symbols", missingDepSyms, "event", eventNameToCancel,
		)
		ps.eventsStates().cancelEvent(eventToCancel)

		// Find all events that depend on eventToCancel
		for eventID := range ps.eventsStates().getAll() {
			depsIDs := events.Core.GetDefinitionByID(eventID).GetDependencies().GetIDs()
			for _, depID := range depsIDs {
				if depID == eventToCancel {
					depsToCancel[eventID] = eventNameToCancel
				}
			}
		}

		// Cancel all events that require eventToCancel
		for eventID, depEventName := range depsToCancel {
			logger.Debugw(
				"Event cancelled because it depends on an previously cancelled event",
				"event", events.Core.GetDefinitionByID(eventID).GetName(),
				"dependency", depEventName,
			)
			ps.eventsStates().cancelEvent(eventID)
		}
	}
}

// getUnavKsymsPerEvtID returns event IDs and symbols that are unavailable to them.
func getUnavKsymsPerEvtID(evtsStates *eventsStates) map[events.ID][]string {
	unavSymsPerEvtID := map[events.ID][]string{}

	for evtID := range evtsStates.getAll() {
		unavailable := getUnavEvtKsymsDeps(evtID)
		if len(unavailable) > 0 {
			unavSymsPerEvtID[evtID] = unavailable
		}
	}

	return unavSymsPerEvtID
}

// getUnavEvtKsymsDeps returns the unavailable symbols for an event.
// TODO: move this to events package (dependencies.go).
func getUnavEvtKsymsDeps(evtID events.ID) []string {
	unavSyms := []string{}
	ksyms, err := ksymbols.GetInstance()
	if err != nil {
		logger.Errorw("Failed to get kallsyms", "error", err)
		return unavSyms
	}

	evtDefSymDeps := events.Core.GetDefinitionByID(evtID).GetDependencies().GetKSymbols()

	for _, symDep := range evtDefSymDeps {
		sym, err := ksyms.GetSymbolByName(symDep.GetSymbolName())
		symName := symDep.GetSymbolName()
		if err != nil {
			// If the symbol is not found, it means it's unavailable.
			unavSyms = append(unavSyms, symName)
			continue
		}
		for _, s := range sym {
			if s.Address == 0 {
				// Same if the symbol is found but its address is 0.
				unavSyms = append(unavSyms, symName)
			}
		}
	}

	return unavSyms
}
