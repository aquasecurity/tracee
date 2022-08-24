package derive

import (
	"path"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"
)

func SymbolsLoaded(soLoader sharedobjs.DynamicSymbolsLoader, watchedSymbols []string, whitelistedLibsPrefixes []string, isDebug bool) deriveFunction {
	gen := initSymbolsLoadedEventGenerator(soLoader, watchedSymbols, whitelistedLibsPrefixes, isDebug)
	return deriveSingleEvent(events.SymbolsLoaded, gen.deriveArgs)
}

// Most specific paths should be at the top, to prevent bugs with iterations over the list
var knownLibrariesDirs = []string{
	"/usr/lib64/",
	"/usr/lib/",
	"/lib64/",
	"/lib/",
}

var knownArchitectureDirs = []string{
	"x86_64-linux-gnu",
	"aarch64-linux-gnu",
	"i386-linux-gnu",
	"i686-linux-gnu",
	"", // non-specific architecture dir
}

// symbolsLoadedEventGenerator is responsible of generating event if shared object loaded to a process
// export one or more from given watched sybmols.
type symbolsLoadedEventGenerator struct {
	soLoader            sharedobjs.DynamicSymbolsLoader
	watchedSymbols      map[string]bool
	pathPrefixWhitelist []string
	librariesWhitelist  []string
	isDebug             bool
}

func initSymbolsLoadedEventGenerator(
	soLoader sharedobjs.DynamicSymbolsLoader,
	watchedSymbols []string,
	whitelistedLibsPrefixes []string,
	isDebug bool) *symbolsLoadedEventGenerator {
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
	return &symbolsLoadedEventGenerator{
		soLoader:            soLoader,
		watchedSymbols:      watchedSymbolsMap,
		pathPrefixWhitelist: prefixes,
		librariesWhitelist:  libraries,
		isDebug:             isDebug,
	}
}

func (symbsLoadedGen *symbolsLoadedEventGenerator) deriveArgs(event trace.Event) ([]interface{}, error) {
	loadingObjectInfo, err := getSharedObjectInfo(event)
	if err != nil {
		return nil, err
	}

	if symbsLoadedGen.isWhitelist(loadingObjectInfo.Path) {
		return nil, nil
	}

	soSyms, err := symbsLoadedGen.soLoader.GetExportedSymbols(loadingObjectInfo)
	if err != nil {
		// TODO: Create a warning upon this error when logger is available

		// This error happens frequently in some environments, so we need to silence it to reduce spam.
		if symbsLoadedGen.isDebug {
			return nil, err
		} else {
			return nil, nil
		}
	}

	var exportedWatchSymbols []string
	for sym := range soSyms {
		if symbsLoadedGen.watchedSymbols[sym] {
			exportedWatchSymbols = append(exportedWatchSymbols, sym)
		}
	}

	if len(exportedWatchSymbols) > 0 {
		return []interface{}{loadingObjectInfo.Path, exportedWatchSymbols}, nil
	} else {
		return nil, nil
	}
}

// isWhitelist check if a SO's path is in the whitelist given in initialization
func (symbsLoadedGen *symbolsLoadedEventGenerator) isWhitelist(soPath string) bool {
	// Check absolute path libraries whitelist
	for _, prefix := range symbsLoadedGen.pathPrefixWhitelist {
		if strings.HasPrefix(soPath, prefix) {
			return true
		}
	}

	// Check if SO is whitelisted library which resides in one of the known libs paths
	if len(symbsLoadedGen.librariesWhitelist) > 0 {
		for _, libsDirectory := range knownLibrariesDirs {
			if strings.HasPrefix(soPath, libsDirectory) {
				for _, archDir := range knownArchitectureDirs {
					archLibDir := path.Join(libsDirectory, archDir)
					if strings.HasPrefix(soPath, archLibDir) {
						for _, wlLib := range symbsLoadedGen.librariesWhitelist {
							if strings.HasPrefix(soPath, path.Join(archLibDir, wlLib)) {
								return true
							}
						}
						break
					}
				}
				break
			}
		}
	}
	return false
}

// getSharedObjectInfo extract from SO loading event the information available about the SO
func getSharedObjectInfo(event trace.Event) (sharedobjs.ObjInfo, error) {
	var objInfo sharedobjs.ObjInfo
	loadedObjectInode, err := parse.ArgUint64Val(&event, "inode")
	if err != nil {
		return objInfo, err
	}
	loadedObjectDevice, err := parse.ArgUint32Val(&event, "dev")
	if err != nil {
		return objInfo, err
	}
	loadedObjectCtime, err := parse.ArgUint64Val(&event, "ctime")
	if err != nil {
		return objInfo, err
	}
	loadedObjectPath, err := parse.ArgStringVal(&event, "pathname")
	if err != nil {
		return objInfo, err
	}
	objInfo = sharedobjs.ObjInfo{
		Id: sharedobjs.ObjID{
			Inode:  loadedObjectInode,
			Device: loadedObjectDevice,
			Ctime:  loadedObjectCtime},
		Path:    loadedObjectPath,
		MountNS: event.MountNS,
	}
	return objInfo, nil
}
