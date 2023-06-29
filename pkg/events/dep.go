package events

import (
	"sync"
	"sync/atomic"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

//
// Dependencies (events, ksyms, tailcalls & capabilities)
//

//
// NOTE:
//
// Within the Dependencies type, there is a single field which thread-safety is guaranteed by the
// field type itself, and not by Dependencies methods: Capabilities. This happens because there are
// currently two options to chose when adding fields to Dependencies:
//
// 1. To have a complex type (array, map, slice, ...) as a Dependencies field and protect it with
//    mutexes that are also internal to Dependencies.
//
// 2. To have a single atomic pointer dereference to a type instance pointer, and rely on its
//    internal synchronization mechanisms (like the Dependencies type).
//

type Dependencies struct {
	events        map[ID]struct{}                 // map[eventID]struct{}
	probes        map[probes.Handle]*Probe        // map[handle]*ProbeDependency
	kSymbols      map[string]*KSymbol             // map[symbolName]*KSymbolDependency
	tailCalls     map[string]map[string]*TailCall // map[mapName]map[progName]*TailCall
	capabilities  *atomic.Pointer[Capabilities]   // pointer to a Capabilities instance
	eventsLock    *sync.RWMutex
	probesLock    *sync.RWMutex
	kSymbolsLock  *sync.RWMutex
	tailCallsLock *sync.RWMutex
}

// NewDependencies creates a new Dependencies object with default values.
func NewDependencies(
	givenEvents []ID,
	givenProbes []*Probe,
	givenKSymbols []*KSymbol,
	givenTailCalls []*TailCall,
	givenCapabilities *Capabilities,
) *Dependencies {
	// Create all needed maps
	events := make(map[ID]struct{})
	prbs := make(map[probes.Handle]*Probe)
	kSymbols := make(map[string]*KSymbol)
	tailCalls := make(map[string]map[string]*TailCall)

	dpds := &Dependencies{
		events:        events,
		probes:        prbs,
		kSymbols:      kSymbols,
		tailCalls:     tailCalls,
		capabilities:  &atomic.Pointer[Capabilities]{},
		eventsLock:    &sync.RWMutex{},
		probesLock:    &sync.RWMutex{},
		kSymbolsLock:  &sync.RWMutex{},
		tailCallsLock: &sync.RWMutex{},
	}

	// Capabilities needs initialization of its internal sync mechanism
	if givenCapabilities == nil {
		givenCapabilities = NewCapabilities(nil)
	}

	dpds.addEvents(givenEvents)
	dpds.addKSymbols(givenKSymbols)
	dpds.addProbes(givenProbes)
	dpds.addTailCalls(givenTailCalls)
	dpds.SetCapabilities(givenCapabilities)

	return dpds
}
