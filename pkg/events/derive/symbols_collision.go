package derive

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/hashicorp/golang-lru/simplelru"
)

// SymbolsCollision generate events for collisions between symbols exported by shared objects loaded to the same
// process.
// The event is triggered by the loading of a shared object, and an event will be created for each shared object
// which has collisions with the newly loaded one.
// For efficiency reasons, the event uses caching that require the `sched_process_exec` event for handling.
func SymbolsCollision(
	soLoader sharedobjs.DynamicSymbolsLoader,
	symbolsBlackList []string,
	symbolsWhiteList []string) DeriveFunction {
	gen := initSOCollisionsEventGenerator(soLoader, symbolsBlackList, symbolsWhiteList)
	return deriveMultipleEvents(events.SymbolsCollision, gen.deriveArgs)
}

// SymbolsCollisionArgsGenerator is the struct responsible to create the SO symbols collisions derived event.
// To do so, it uses multiple caches to accelerate performance and reduce chances for failure.
type SymbolsCollisionArgsGenerator struct {
	soLoader          sharedobjs.DynamicSymbolsLoader
	processesSOsCache processesLoadedObjectsCache
	collisionsCache   sharedObjectsCollisionsCache
	symbolsBlackList  map[string]bool
	symbolsWhiteList  map[string]bool
	returnedErrors    map[string]bool
}

func initSOCollisionsEventGenerator(
	soLoader sharedobjs.DynamicSymbolsLoader,
	symbolsBlackList []string,
	symbolsWhiteList []string) *SymbolsCollisionArgsGenerator {
	lruCallback := simplelru.EvictCallback(func(key interface{}, value interface{}) {})
	processLoadedObjectsLRU, _ := simplelru.NewLRU(1024, lruCallback)
	objectCollisionsLRU, _ := simplelru.NewLRU(1024, lruCallback)
	symbolsBlackListMap := make(map[string]bool)
	for _, sym := range symbolsBlackList {
		symbolsBlackListMap[sym] = true
	}
	symbolsWhiteListMap := make(map[string]bool)
	for _, sym := range symbolsWhiteList {
		symbolsWhiteListMap[sym] = true
	}
	return &SymbolsCollisionArgsGenerator{
		soLoader:          soLoader,
		processesSOsCache: processesLoadedObjectsCache{processLoadedObjectsLRU},
		collisionsCache:   sharedObjectsCollisionsCache{objectCollisionsLRU},
		symbolsBlackList:  symbolsBlackListMap,
		symbolsWhiteList:  symbolsWhiteListMap,
		returnedErrors:    make(map[string]bool),
	}
}

func (soColGen *SymbolsCollisionArgsGenerator) deriveArgs(event trace.Event) ([][]interface{}, []error) {
	switch events.ID(event.EventID) {
	case events.SharedObjectLoaded:
		return soColGen.handleSOLoaded(event)
	case events.SchedProcessExec:
		return soColGen.handleExec(event)
	default:
		return nil, []error{fmt.Errorf("received unexpected event - \"%s\"", event.EventName)}
	}
}

// handleSOLoaded check when a shared object is loaded into a process if some of its exported symbols collide with
// previously loaded shared object.
// An event will be created for each SO it has collisions with.
// The main efficiency features it uses is caching examined SOs symbols and collision check results.
// The hope is that after few processes are executed, all major libraries in the system will be cached already
// and most libraries combinations collisions check results will be cached too.
func (soColGen *SymbolsCollisionArgsGenerator) handleSOLoaded(event trace.Event) ([][]interface{}, []error) {
	loadingObjectInfo, err := getSharedObjectInfo(event)
	if err != nil {
		return nil, []error{err}
	}

	processLoadedObjects, ok := soColGen.processesSOsCache.GetProcessLoadedObjects(event.HostProcessID)
	if !ok {
		processLoadedObjects = []sharedobjs.ObjInfo{}
	}
	newProcessLoadedObjects := append(processLoadedObjects, loadingObjectInfo)
	soColGen.processesSOsCache.SetProcessLoadedObjects(event.HostProcessID, newProcessLoadedObjects)

	// Exported symbols will be updated if needed in the findSOCollisions method
	loadingObject := loadingSOInstance{ObjInfo: loadingObjectInfo}

	var collisionEventsArgs [][]interface{}
	var errs []error
	for _, lsoInfo := range processLoadedObjects {
		collisions, err := soColGen.findSOCollisions(&loadingObject, lsoInfo)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(collisions) > 0 {
			collisionEventsArgs = append(collisionEventsArgs, []interface{}{loadingObjectInfo.Path, lsoInfo.Path, collisions})
		}
	}

	return collisionEventsArgs, errs
}

// handleExec delete saved process loaded objects in case of execve, because entire memory is overwritten in this case
func (soColGen *SymbolsCollisionArgsGenerator) handleExec(event trace.Event) ([][]interface{}, []error) {
	soColGen.processesSOsCache.SetProcessLoadedObjects(event.HostProcessID, []sharedobjs.ObjInfo{})
	return nil, nil
}

// findSOCollisions check for collisions between new SO loaded to existing one in the most efficient way possible.
// It updates the given SO if symbols are missing.
func (soColGen *SymbolsCollisionArgsGenerator) findSOCollisions(so *loadingSOInstance, loadedSO sharedobjs.ObjInfo) ([]string, error) {
	var err error
	collisions, ok := soColGen.collisionsCache.GetCollision(so.Id, loadedSO.Id)
	if !ok {
		if so.ExportedSymbols == nil {
			so.ExportedSymbols, err = soColGen.soLoader.GetExportedSymbols(so.ObjInfo)
			if err != nil {
				// TODO: rate limit frequent errors for overloaded envs
				_, ok := soColGen.returnedErrors[err.Error()]
				if !ok {
					soColGen.returnedErrors[err.Error()] = true
					logger.Warn("symbols_loaded", "object loaded", so.ObjInfo, "error", err.Error())
				} else {
					logger.Debug("symbols_loaded", "object loaded", so.ObjInfo, "error", err.Error())
				}
				return nil, nil
			}
			so.FilterSymbols(soColGen.symbolsBlackList)
			so.FilterOutSymbols(soColGen.symbolsWhiteList)
			if err != nil {
				return nil, err
			}
		}
		lsoSyms, err := soColGen.soLoader.GetExportedSymbols(loadedSO)
		if err != nil {
			// TODO: rate limit frequent errors for overloaded envs
			_, ok := soColGen.returnedErrors[err.Error()]
			if !ok {
				soColGen.returnedErrors[err.Error()] = true
				logger.Warn("symbols_loaded", "object loaded", loadedSO, "error", err.Error())
			} else {
				logger.Debug("symbols_loaded", "object loaded", loadedSO, "error", err.Error())
			}
			return nil, nil
		}
		lso := loadingSOInstance{ObjInfo: loadedSO, ExportedSymbols: lsoSyms}
		lso.FilterSymbols(soColGen.symbolsBlackList)
		lso.FilterOutSymbols(soColGen.symbolsWhiteList)
		collisions = so.GetCollisions(lso)
		soColGen.collisionsCache.AddCollisions(so.Id, loadedSO.Id, collisions)
	}
	return collisions, nil
}

// processesLoadedObjectsCache is a cache for shared objects loaded to a process
type processesLoadedObjectsCache struct {
	cache *simplelru.LRU
}

// GetProcessLoadedObjects get the shared SOs loaded to the process, and if the process existed in the cache.
func (pcache *processesLoadedObjectsCache) GetProcessLoadedObjects(pid int) ([]sharedobjs.ObjInfo, bool) {
	var loadedObjects []sharedobjs.ObjInfo
	loadedObjectsIface, ok := pcache.cache.Get(pid)
	if ok {
		loadedObjects = loadedObjectsIface.([]sharedobjs.ObjInfo)
		return loadedObjects, true
	}
	return nil, false
}

func (pcache *processesLoadedObjectsCache) SetProcessLoadedObjects(pid int, loadedObjects []sharedobjs.ObjInfo) {
	pcache.cache.Add(pid, loadedObjects)
}

// collisionsKey is the key for the sharedObjectsCollisionsCache cache.
// The order is meaningful, so when using it all options should be checked.
type collisionsKey struct {
	obj1 sharedobjs.ObjID
	obj2 sharedobjs.ObjID
}

// sharedObjectsCollisionsCache is a cache for collision checks which were performed already
type sharedObjectsCollisionsCache struct {
	cache *simplelru.LRU
}

// AddCollisions add the collisions between 2 shared objects to the cache.
// It will override previous cached collision if there is one, and create new one if not.
func (socCache sharedObjectsCollisionsCache) AddCollisions(obj1 sharedobjs.ObjID,
	obj2 sharedobjs.ObjID,
	collisions []string) {
	key, _, ok := socCache.getObjCollisions(obj1, obj2)
	if !ok {
		key = collisionsKey{obj1: obj1, obj2: obj2}
	}
	socCache.setObjCollisions(key, collisions)
}

// GetCollision return the symbols collided between 2 shared objects from the cache if there are any.
// Return bool indication if the collision existed in the cache.
func (socCache sharedObjectsCollisionsCache) GetCollision(obj1 sharedobjs.ObjID,
	obj2 sharedobjs.ObjID) ([]string, bool) {
	_, collisions, ok := socCache.getObjCollisions(obj1, obj2)
	if ok {
		return collisions, true
	}
	return nil, false
}

// Get from the cache the collisions check result of the object with other shared objects.
// Return the key with which the collision was cached (if it was), the collisions and if
// there was a cached collision at all.
func (socCache sharedObjectsCollisionsCache) getObjCollisions(obj1 sharedobjs.ObjID,
	obj2 sharedobjs.ObjID) (
	collisionsKey, []string, bool) {
	key := collisionsKey{
		obj1: obj1,
		obj2: obj2,
	}
	collisionsIface, ok := socCache.cache.Get(key)
	if !ok {
		key = collisionsKey{
			obj1: obj2,
			obj2: obj1,
		}
		collisionsIface, ok = socCache.cache.Get(key)
	}
	if ok {
		collisions := collisionsIface.([]string)
		return key, collisions, true
	}
	return collisionsKey{}, nil, false
}

func (socCache sharedObjectsCollisionsCache) setObjCollisions(key collisionsKey,
	collisions []string) {
	socCache.cache.Add(key, collisions)
}

// loadingSOInstance is the whole relevant information collected on a loaded SO
type loadingSOInstance struct {
	sharedobjs.ObjInfo
	ExportedSymbols map[string]bool
}

func (so *loadingSOInstance) ContainsSymbol(sym string) bool {
	_, ok := so.ExportedSymbols[sym]
	return ok
}

func (so *loadingSOInstance) GetSymbols() []string {
	symbols := make([]string, len(so.ExportedSymbols))
	i := 0
	for sym := range so.ExportedSymbols {
		symbols[i] = sym
		i += 1
	}
	return symbols
}

func (so *loadingSOInstance) GetCollisions(obj loadingSOInstance) []string {
	var collidedSymbols []string
	for _, sym := range so.GetSymbols() {
		if obj.ContainsSymbol(sym) {
			collidedSymbols = append(collidedSymbols, sym)
		}
	}
	return collidedSymbols
}

// FilterSymbols remove all exported symbols which are not in the filter map
func (so *loadingSOInstance) FilterSymbols(filterSymbols map[string]bool) {
	if len(filterSymbols) == 0 {
		return
	}
	filteredSymbols := make(map[string]bool)
	for filterSym := range filterSymbols {
		if so.ExportedSymbols[filterSym] {
			filteredSymbols[filterSym] = true
		}
	}
	so.ExportedSymbols = filteredSymbols
}

// FilterOutSymbols remove all exported symbols which are in the filter map
func (so *loadingSOInstance) FilterOutSymbols(filterSymbols map[string]bool) {
	for exSymbol := range so.ExportedSymbols {
		if filterSymbols[exSymbol] {
			delete(so.ExportedSymbols, exSymbol)
		}
	}
}
