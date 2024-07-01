package derive

import (
	"errors"
	"path"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"
)

func SymbolsLoaded(
	soLoader sharedobjs.DynamicSymbolsLoader,
	pManager *policy.PolicyManager,
) DeriveFunction {
	symbolsLoadedFilters := map[string]filters.Filter[*filters.StringFilter]{}

	for it := pManager.CreateAllIterator(); it.HasNext(); {
		p := it.Next()
		f := p.DataFilter.GetEventFilters(events.SymbolsLoaded)
		maps.Copy(symbolsLoadedFilters, f)
	}

	loadWatchedSymbols := []string{}
	loadWhitelistedLibs := []string{}

	if len(symbolsLoadedFilters) > 0 {
		watchedSymbolsFilter, ok := symbolsLoadedFilters["symbols"].(*filters.StringFilter)
		if watchedSymbolsFilter != nil && ok {
			loadWatchedSymbols = watchedSymbolsFilter.Equal()
		}
		whitelistedLibsFilter, ok := symbolsLoadedFilters["library_path"].(*filters.StringFilter)
		if whitelistedLibsFilter != nil && ok {
			loadWhitelistedLibs = whitelistedLibsFilter.NotEqual()
		}
	}

	gen := initSymbolsLoadedEventGenerator(soLoader, loadWatchedSymbols, loadWhitelistedLibs)

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

// symbolsLoadedEventGenerator is responsible of generating event if shared object loaded to a
// process export one or more from given watched symbols.
type symbolsLoadedEventGenerator struct {
	soLoader            sharedobjs.DynamicSymbolsLoader
	watchedSymbols      map[string]bool
	pathPrefixWhitelist []string
	librariesWhitelist  []string
	returnedErrors      map[string]bool
	libsCache           *lru.Cache[sharedobjs.ObjID, []string]
}

func initSymbolsLoadedEventGenerator(
	soLoader sharedobjs.DynamicSymbolsLoader,
	watchedSymbols []string,
	whitelistedLibsPrefixes []string,
) *symbolsLoadedEventGenerator {
	watchedSymbolsMap := make(map[string]bool)
	for _, sym := range watchedSymbols {
		watchedSymbolsMap[sym] = true
	}

	var libraries, prefixes []string
	for _, wlPath := range whitelistedLibsPrefixes {
		if strings.HasPrefix(wlPath, "/") {
			prefixes = append(prefixes, wlPath)
		} else {
			libraries = append(libraries, wlPath)
		}
	}

	cacheLRU, _ := lru.New[sharedobjs.ObjID, []string](10240)

	return &symbolsLoadedEventGenerator{
		soLoader:            soLoader,
		watchedSymbols:      watchedSymbolsMap,
		pathPrefixWhitelist: prefixes,
		librariesWhitelist:  libraries,
		returnedErrors:      make(map[string]bool),
		libsCache:           cacheLRU,
	}
}

func (symbsLoadedGen *symbolsLoadedEventGenerator) deriveArgs(
	event trace.Event,
) (
	[]interface{}, error,
) {
	loadingObjectInfo, err := getSharedObjectInfo(event)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	if symbsLoadedGen.isWhitelist(loadingObjectInfo.Path) {
		return nil, nil
	}

	matchedSyms, ok := symbsLoadedGen.getSymbolsFromCache(loadingObjectInfo.Id)
	if ok {
		if len(matchedSyms) > 0 {
			hash, _ := parse.ArgVal[string](event.Args, "sha256")
			return []interface{}{loadingObjectInfo.Path, matchedSyms, hash}, nil
		}
		return nil, nil
	}

	soSyms, err := symbsLoadedGen.soLoader.GetExportedSymbols(loadingObjectInfo)
	// This error happens frequently in some environments, so we need to silence it to reduce spam.
	// Either way, this is not a critical error so we don't return it.
	if err != nil {
		// High level languages like Java might load non-ELF files
		// There is no need to log errors for such cases
		var notElfErr *sharedobjs.UnsupportedFileError
		if errors.As(err, &notElfErr) {
			return nil, nil
		}
		// TODO: rate limit frequent errors for overloaded envs
		_, ok := symbsLoadedGen.returnedErrors[err.Error()]
		if !ok {
			symbsLoadedGen.returnedErrors[err.Error()] = true
			logger.Debugw("symbols_loaded", "object loaded", loadingObjectInfo, "error", err.Error())
		}
		return nil, nil
	}

	var exportedWatchSymbols []string

	for sym := range soSyms {
		if symbsLoadedGen.watchedSymbols[sym] {
			exportedWatchSymbols = append(exportedWatchSymbols, sym)
		}
	}

	symbsLoadedGen.libsCache.Add(loadingObjectInfo.Id, exportedWatchSymbols)
	if len(exportedWatchSymbols) > 0 {
		hash, _ := parse.ArgVal[string](event.Args, "sha256")
		return []interface{}{loadingObjectInfo.Path, exportedWatchSymbols, hash}, nil
	}

	return nil, nil
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

// getSymbolsFromCache query the cache for check results of specified object.
// Return the watched symbols found in the object, and if it was found in the cache.
func (symbsLoadedGen *symbolsLoadedEventGenerator) getSymbolsFromCache(id sharedobjs.ObjID) ([]string, bool) {
	return symbsLoadedGen.libsCache.Get(id)
}

// getSharedObjectInfo extract from SO loading event the information available about the SO
func getSharedObjectInfo(event trace.Event) (sharedobjs.ObjInfo, error) {
	var objInfo sharedobjs.ObjInfo

	loadedObjectInode, err := parse.ArgVal[uint64](event.Args, "inode")
	if err != nil {
		return objInfo, errfmt.WrapError(err)
	}
	loadedObjectDevice, err := parse.ArgVal[uint32](event.Args, "dev")
	if err != nil {
		return objInfo, errfmt.WrapError(err)
	}
	loadedObjectCtime, err := parse.ArgVal[uint64](event.Args, "ctime")
	if err != nil {
		return objInfo, errfmt.WrapError(err)
	}
	loadedObjectPath, err := parse.ArgVal[string](event.Args, "pathname")
	if err != nil {
		return objInfo, errfmt.WrapError(err)
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
