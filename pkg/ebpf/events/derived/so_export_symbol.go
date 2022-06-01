package derived

import (
	"path"
	"strings"

	"github.com/aquasecurity/tracee/pkg/utils/shared_objects"
	"github.com/aquasecurity/tracee/types/trace"
)

var knownLibrariesDirs = []string{
	"/lib/",
	"/lib64/",
	"/usr/lib/",
	"/usr/lib64/",
	"/usr/lib/x86_64-linux-gnu/",
}

// SOExportWatchedSymbolsEventGenerator is responsible of generating event if shared object loaded to a process
// export one or more from given watched sybmols.
type SOExportWatchedSymbolsEventGenerator struct {
	symbolExportEventSkeleton EventSkeleton
	soLoader                  shared_objects.ISOExportSymbolsLoader
	watchedSymbols            map[string]bool
	pathPrefixWhitelist       []string
	librariesWhitelist        []string
}

func InitSOExportWatchedSymbolsEventGenerator(
	eSkel EventSkeleton,
	soLoader shared_objects.ISOExportSymbolsLoader,
	watchedSymbols []string,
	whitelistedLibsPrefixes []string) SOExportWatchedSymbolsEventGenerator {
	watchedSymbolsMap := make(map[string]bool)
	for _, sym := range watchedSymbols {
		watchedSymbolsMap[sym] = true
	}
	var libraries, prefixes []string
	for _, path := range whitelistedLibsPrefixes {
		if strings.HasPrefix(path, "/") {
			prefixes = append(prefixes, path)
		} else {
			libraries = append(libraries, path)
		}
	}
	return SOExportWatchedSymbolsEventGenerator{
		symbolExportEventSkeleton: eSkel,
		soLoader:                  soLoader,
		watchedSymbols:            watchedSymbolsMap,
		pathPrefixWhitelist:       prefixes,
		librariesWhitelist:        libraries,
	}
}

// GenerateEvents generate event if loaded shared object export one or more of the watched symbols.
func (soExSymbolGen *SOExportWatchedSymbolsEventGenerator) GenerateEvents(event trace.Event) ([]trace.Event, bool, error) {
	loadingObjectInfo, err := getSharedObjectExInfo(event)
	if err != nil {
		return []trace.Event{}, false, err
	}

	if soExSymbolGen.isWhitelist(loadingObjectInfo.Path) {
		return []trace.Event{}, false, nil
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

// isWhitelist check if a SO's path is in the whitelist given in initialization
func (soExSymbolGen SOExportWatchedSymbolsEventGenerator) isWhitelist(soPath string) bool {
	// Check absolute path libraries whitelist
	for _, prefix := range soExSymbolGen.pathPrefixWhitelist {
		if strings.HasPrefix(soPath, prefix) {
			return true
		}
	}

	// Check if SO is whitelisted library which resides in one of the known libs paths
	if len(soExSymbolGen.librariesWhitelist) > 0 {
		for _, libsDirectory := range knownLibrariesDirs {
			if strings.HasPrefix(soPath, libsDirectory) {
				for _, wlLib := range soExSymbolGen.librariesWhitelist {
					if strings.HasPrefix(soPath, path.Join(libsDirectory, wlLib)) {
						return true
					}
				}
				break
			}
		}
	}
	return false
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
