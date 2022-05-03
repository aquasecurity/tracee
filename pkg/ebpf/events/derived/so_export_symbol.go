package derived

import (
	"github.com/aquasecurity/tracee/pkg/utils/shared_objects"
	"github.com/aquasecurity/tracee/types/trace"
)

// SOExportWatchedSymbolsEventGenerator is responsible of generating event if shared object loaded to a process
// export one or more from given watched sybmols.
type SOExportWatchedSymbolsEventGenerator struct {
	symbolExportEventSkeleton EventSkeleton
	soLoader                  shared_objects.ISOExportSymbolsLoader
	watchedSymbols            map[string]bool
}

func InitSOExportWatchedSymbolsEventGenerator(eSkel EventSkeleton, soLoader shared_objects.ISOExportSymbolsLoader, watchedSymbols []string) SOExportWatchedSymbolsEventGenerator {
	watchedSymbolsMap := make(map[string]bool)
	for _, sym := range watchedSymbols {
		watchedSymbolsMap[sym] = true
	}
	return SOExportWatchedSymbolsEventGenerator{
		symbolExportEventSkeleton: eSkel,
		soLoader:                  soLoader,
		watchedSymbols:            watchedSymbolsMap,
	}
}

// GenerateEvents generate event if loaded shared object export one or more of the watched symbols.
func (soExSymbolGen *SOExportWatchedSymbolsEventGenerator) GenerateEvents(event trace.Event) ([]trace.Event, bool, error) {
	loadingObjectInfo, err := getSharedObjectExInfo(event)
	if err != nil {
		return []trace.Event{}, false, err
	}

	soSyms, err := soExSymbolGen.soLoader.GetSOExSymbols(loadingObjectInfo)
	if err != nil {
		return []trace.Event{}, false, err
	}

	var exportedWatchSymbols []string
	for sym := range soSyms {
		if soExSymbolGen.watchedSymbols[sym] {
			exportedWatchSymbols = append(exportedWatchSymbols, sym)
		}
	}

	if len(exportedWatchSymbols) > 0 {
		return []trace.Event{soExSymbolGen.buildSOExportWatchSymbolsEvent(event, loadingObjectInfo, exportedWatchSymbols)}, true, nil
	} else {
		return []trace.Event{}, false, nil
	}
}

func (soExSymbolGen *SOExportWatchedSymbolsEventGenerator) buildSOExportWatchSymbolsEvent(loadEvent trace.Event, loadingObject shared_objects.SoExaminationInfo, watchedExportedSymbols []string) trace.Event {
	de := loadEvent
	de.EventName = soExSymbolGen.symbolExportEventSkeleton.Name
	de.EventID = soExSymbolGen.symbolExportEventSkeleton.ID
	de.ReturnValue = 0
	de.StackAddresses = make([]uint64, 1)
	de.Args = []trace.Argument{
		{ArgMeta: soExSymbolGen.symbolExportEventSkeleton.Params[0], Value: loadingObject.Path},
		{ArgMeta: soExSymbolGen.symbolExportEventSkeleton.Params[1], Value: watchedExportedSymbols},
	}
	return de
}
