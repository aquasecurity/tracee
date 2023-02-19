package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/filterscope"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/hashicorp/golang-lru/simplelru"
	"golang.org/x/exp/maps"
)

//
// SymbolsCollision --------------------------------------------------------------------------------
//
// Generates events for collisions between symbols exported by shared objects loaded to the same
// process virtual memory address space.
//
// One event is created for each symbol collision, and all of them are triggered by the loading of a
// shared object to a process. For efficiency reasons, the event uses caching that require the
// `sched_process_exec` event for handling.
//

func SymbolsCollision(soLoader sharedobjs.DynamicSymbolsLoader, fScopes *filterscope.FilterScopes,
) DeriveFunction {

	symbolsCollisionFilters := map[string]filters.Filter{}

	// pick white and black lists from the filters (TODO: change this)
	for fScope := range fScopes.Map() {
		f := fScope.ArgFilter.GetEventFilters(events.SymbolsCollision)
		maps.Copy(symbolsCollisionFilters, f)
	}

	symbolsWhitelist := []string{}
	symbolsBlacklist := []string{}

	filter, ok := symbolsCollisionFilters["symbols"].(*filters.StringFilter)
	if filter != nil && ok {
		symbolsWhitelist = filter.Equal()
		symbolsBlacklist = filter.NotEqual()
	}

	gen := initSOCollisionsEventGenerator(soLoader, symbolsBlacklist, symbolsWhitelist)

	return deriveMultipleEvents(events.SymbolsCollision, gen.deriveArgs)
}

//
// SymbolsCollisionArgsGenerator -------------------------------------------------------------------
//

// SymbolsCollisionArgsGenerator creates the shared object symbols collisions derived events. To do
// so, it uses multiple caches to accelerate performance and reduce chances for failure.
type SymbolsCollisionArgsGenerator struct {
	soLoader               sharedobjs.DynamicSymbolsLoader
	loadedObjsPerProcCache loadedObjsPerProcessCache // cache of loaded shared objects per process
	collisionChecksCache   collisionChecksCache      // cache of symbols collisions
	symbolsBlacklistMap    map[string]bool           // will delete symbols NOT in this map
	symbolsWhitelistMap    map[string]bool           // will delete symbols IN this map
	returnedErrorsMap      map[string]bool           // keep track of logged/debugged errors
}

func initSOCollisionsEventGenerator(
	soLoader sharedobjs.DynamicSymbolsLoader,
	symbolsBlackList []string,
	symbolsWhiteList []string,
) *SymbolsCollisionArgsGenerator {

	noCallback := simplelru.EvictCallback(func(key interface{}, value interface{}) {})
	loadedObsPerProcessLRU, _ := simplelru.NewLRU(1024, noCallback)
	collisionChecksLRU, _ := simplelru.NewLRU(1024, noCallback)

	symbolsBlackListMap := make(map[string]bool)
	for _, sym := range symbolsBlackList {
		symbolsBlackListMap[sym] = true
	}

	symbolsWhiteListMap := make(map[string]bool)
	for _, sym := range symbolsWhiteList {
		symbolsWhiteListMap[sym] = true
	}

	return &SymbolsCollisionArgsGenerator{
		soLoader:               soLoader,
		loadedObjsPerProcCache: loadedObjsPerProcessCache{loadedObsPerProcessLRU},
		collisionChecksCache:   collisionChecksCache{collisionChecksLRU},
		symbolsBlacklistMap:    symbolsBlackListMap,
		symbolsWhitelistMap:    symbolsWhiteListMap,
		returnedErrorsMap:      make(map[string]bool),
	}
}

// deriveArgs calls the appropriate derivation handler depending on the event type.
func (gen *SymbolsCollisionArgsGenerator) deriveArgs(event trace.Event) ([][]interface{}, []error) {
	switch events.ID(event.EventID) {
	case events.SharedObjectLoaded:
		return gen.handleShObjLoaded(event) // manages symbol collisions caches and generate events
	case events.SchedProcessExec:
		return gen.handleExec(event) // evicts saved data (loaded shared objects) for the process
	}

	return nil, []error{fmt.Errorf("received unexpected event - \"%s\"", event.EventName)}
}

// handleShObjLoaded handles the shared object loaded event (from mmap).
func (gen *SymbolsCollisionArgsGenerator) handleShObjLoaded(event trace.Event) (
	[][]interface{}, []error,
) {
	// When a shared object is loaded into a process virtual memory address space, check if some of
	// the loaded shared object exported symbols collide with symbols from previously loaded shared
	// objects of the same process.

	loadingObjectInfo, err := getSharedObjectInfo(event) // info about shared object being loaded
	if err != nil {
		return nil, []error{err}
	}

	// pick loaded shared objects of the process
	loadedShObjsInfo, ok := gen.loadedObjsPerProcCache.GetLoadedObjsPerProcess(event.HostProcessID)
	if !ok {
		loadedShObjsInfo = []sharedobjs.ObjInfo{}
	}

	// new list including object being loaded, add new list to shared objects cache per process
	newLoadedObjs := append(loadedShObjsInfo, loadingObjectInfo)
	gen.loadedObjsPerProcCache.SetProcessLoadedObjects(event.HostProcessID, newLoadedObjs)

	loadingObject := &loadingSharedObj{
		ObjInfo: loadingObjectInfo,
		// exportedSymbols: will be updated by findShObjsCollisions
	}

	var collisionEventsArgs [][]interface{} // multiple derived events
	var errs []error

	for _, loadedShObjInfo := range loadedShObjsInfo {
		collisions, err := gen.findShObjsCollisions(loadingObject, loadedShObjInfo)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(collisions) > 0 {
			// An event will be created for each shared object it has collisions with. The main
			// efficiency features it uses:
			//
			// - caching examined, and per process, shared object symbols.
			// - collision check results caching between existing shared objects.
			//
			// The hope is that, after few processes are executed, all major libraries in the system
			// are cached and most libraries combinations results are cached too.
			collisionEventsArgs = append(collisionEventsArgs,
				[]interface{}{
					loadingObjectInfo.Path, // loaded path (string)
					loadedShObjInfo.Path,   // collision path (string)
					collisions,             // symbols (string)
				},
			)
		}
	}

	return collisionEventsArgs, errs
}

// findShObjsCollisions checks for symbols collisions between new shared object, being loaded into
// the virtual memory address space of a process, AND an existing already loaded shared object of
// the same process. It tries to do optimize efficiency by caching collision results, to be used in
// a near future. It also updates the given shared object if symbols are missing.
func (gen *SymbolsCollisionArgsGenerator) findShObjsCollisions(
	loadingShObj *loadingSharedObj, loadedShObjInfo sharedobjs.ObjInfo,
) (
	[]string, error,
) {
	var err error

	// ObjId contains: Inode, Device and Ctime. Collisions are unique until a sh object file changes.
	collisions, ok := gen.collisionChecksCache.GetShObjsCollisions(loadingShObj.Id, loadedShObjInfo.Id)

	if !ok {
		// get exported symbols from the shared object BEING loaded
		loadingShObj.exportedSymbols, err = gen.soLoader.GetExportedSymbols(loadingShObj.ObjInfo)
		if err != nil {
			// TODO: rate limit frequent errors for overloaded envs
			_, ok := gen.returnedErrorsMap[err.Error()]
			if !ok {
				gen.returnedErrorsMap[err.Error()] = true
				logger.Warn("symbols_loaded", "object loaded", loadingShObj.ObjInfo, "error", err.Error())
			} else {
				logger.Debug("symbols_loaded", "object loaded", loadingShObj.ObjInfo, "error", err.Error())
			}
			return nil, err
		}
		loadingShObj.FilterSymbols(gen.symbolsBlacklistMap)    // del symbols NOT in blacklist
		loadingShObj.FilterOutSymbols(gen.symbolsWhitelistMap) // del symbols IN the white list

		// get exported symbols from the shared object ALREADY loaded
		loadedExportedSyms, err := gen.soLoader.GetExportedSymbols(loadedShObjInfo)
		if err != nil {
			// TODO: rate limit frequent errors for overloaded envs
			_, ok := gen.returnedErrorsMap[err.Error()]
			if !ok {
				gen.returnedErrorsMap[err.Error()] = true
				logger.Warn("symbols_loaded", "object loaded", loadedShObjInfo, "error", err.Error())
			} else {
				logger.Debug("symbols_loaded", "object loaded", loadedShObjInfo, "error", err.Error())
			}
			return nil, nil
		}

		// create a loadingSharedObj from the already loaded shared object (to get collisions)
		loadedShObj := loadingSharedObj{ObjInfo: loadedShObjInfo, exportedSymbols: loadedExportedSyms}
		loadedShObj.FilterSymbols(gen.symbolsBlacklistMap)    // del symbols NOT in blacklist
		loadedShObj.FilterOutSymbols(gen.symbolsWhitelistMap) // del symbols IN the white list

		collisions = loadingShObj.GetCollisions(loadedShObj)

		// cache collision results
		gen.collisionChecksCache.AddCollisions(loadingShObj.Id, loadedShObjInfo.Id, collisions)
	}

	return collisions, nil // cached or just calculated
}

// handleExec handles the execve() system call event.
func (gen *SymbolsCollisionArgsGenerator) handleExec(event trace.Event) (
	[][]interface{}, []error,
) {
	// Delete (set to empty) a process saved data (loaded shared objects information) for the
	// process if it calls execve(). This is needed because all the virtual memory address space of
	// such process will vanish and the saved data will be useless.
	gen.loadedObjsPerProcCache.SetProcessLoadedObjects(event.HostProcessID, []sharedobjs.ObjInfo{})

	return nil, nil
}

//
// Already loaded shared objects, per process, cache -----------------------------------------------
//

type loadedObjsPerProcessCache struct {
	cache *simplelru.LRU
}

// GetLoadedObjsPerProcess returns the shared objects already loaded in a given process vm space.
func (procLoadedObjsCache *loadedObjsPerProcessCache) GetLoadedObjsPerProcess(
	pid int,
) (
	[]sharedobjs.ObjInfo, bool,
) {
	var loadedObjs []sharedobjs.ObjInfo

	loadedObjsIface, ok := procLoadedObjsCache.cache.Get(pid) // loaded objs per process (ObjInfo)
	if ok {
		loadedObjs = loadedObjsIface.([]sharedobjs.ObjInfo)
		return loadedObjs, true // true if process existed in the cache
	}

	return nil, false
}

// SetProcessLoadedObjects sets the shared objects loaded in one process vm address space.
func (procLoadedObjsCache *loadedObjsPerProcessCache) SetProcessLoadedObjects(
	pid int, loadedObjects []sharedobjs.ObjInfo,
) {
	procLoadedObjsCache.cache.Add(pid, loadedObjects)
}

//
// Shared Object Pairs collisions checks cache -----------------------------------------------------
//

type collisionsKey struct {
	obj1 sharedobjs.ObjID // order is meaningful, compare obj1 to obj2 and obj2 to obj1
	obj2 sharedobjs.ObjID
}

type collisionChecksCache struct {
	cache *simplelru.LRU
}

// AddCollisions adds collisions between 2 shared objects to the cache.
func (socCache collisionChecksCache) AddCollisions(
	obj1 sharedobjs.ObjID,
	obj2 sharedobjs.ObjID,
	collisions []string,
) {
	key, _, ok := socCache.getObjCollisionsAndCollisionKey(obj1, obj2)
	if !ok {
		// creates a new collision if it does not exist yet
		key = collisionsKey{obj1: obj1, obj2: obj2}
	}
	// overrides previously cached collisions
	socCache.setObjCollisions(key, collisions)
}

// GetShObjsCollisions returns the collisions between 2 shared objects from the cache.
func (socCache collisionChecksCache) GetShObjsCollisions(
	obj1 sharedobjs.ObjID,
	obj2 sharedobjs.ObjID,
) (
	[]string, bool,
) {
	_, collisions, ok := socCache.getObjCollisionsAndCollisionKey(obj1, obj2)
	if ok {
		return collisions, true
	}

	return nil, false // no collisions found
}

// getObjCollisionsAndCollisionKey gets the collisions between 2 shared objects, and the cache key.
func (socCache collisionChecksCache) getObjCollisionsAndCollisionKey(
	obj1 sharedobjs.ObjID,
	obj2 sharedobjs.ObjID,
) (
	collisionsKey, []string, bool,
) {
	key := collisionsKey{
		obj1: obj1, // compare obj1 to obj2
		obj2: obj2,
	}
	collisionsIface, ok := socCache.cache.Get(key)
	if !ok {
		key = collisionsKey{ // try comparing obj2 to obj1
			obj1: obj2,
			obj2: obj1,
		}
		collisionsIface, ok = socCache.cache.Get(key)
	}
	if ok {
		collisions := collisionsIface.([]string)
		return key, collisions, true
	}

	return collisionsKey{}, nil, false // no collisions found
}

// setObjCollisions sets the collisions between 2 shared objects in the cache.
func (socCache collisionChecksCache) setObjCollisions(key collisionsKey, collisions []string) {
	socCache.cache.Add(key, collisions)
}

//
// Info about a shared object being loaded in a process virtual memory address space ---------------
//

type loadingSharedObj struct { // extends ObjInfo
	sharedobjs.ObjInfo
	exportedSymbols map[string]bool
}

// ContainsSymbol returns true if the shared object being loaded contains the given symbol.
func (so *loadingSharedObj) ContainsSymbol(sym string) bool {
	_, ok := so.exportedSymbols[sym]
	return ok
}

// GetSymbols returns the list of exported symbols of the shared object being loaded.
func (so *loadingSharedObj) GetSymbols() []string {
	symbols := make([]string, len(so.exportedSymbols))

	i := 0
	for sym := range so.exportedSymbols {
		symbols[i] = sym
		i += 1
	}

	return symbols
}

// GetCollisions returns the list of symbols which collide with the given shared object.
func (so *loadingSharedObj) GetCollisions(obj loadingSharedObj) []string {
	var collidedSymbols []string

	for _, sym := range so.GetSymbols() {
		if obj.ContainsSymbol(sym) {
			collidedSymbols = append(collidedSymbols, sym)
		}
	}

	return collidedSymbols
}

// FilterSymbols removes all exported symbols which ARE NOT in the filter map.
func (so *loadingSharedObj) FilterSymbols(filterSymbols map[string]bool) {
	if len(filterSymbols) == 0 {
		return
	}

	filteredSymbols := make(map[string]bool)
	for filterSym := range filterSymbols {
		if so.exportedSymbols[filterSym] {
			filteredSymbols[filterSym] = true
		}
	}

	so.exportedSymbols = filteredSymbols
}

// FilterOutSymbols removes all exported symbols which ARE in the filter map.
func (so *loadingSharedObj) FilterOutSymbols(filterSymbols map[string]bool) {
	for exSymbol := range so.exportedSymbols {
		if filterSymbols[exSymbol] {
			delete(so.exportedSymbols, exSymbol)
		}
	}
}
