package derived

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events/parsing"
	"github.com/aquasecurity/tracee/pkg/utils/shared_objects"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/hashicorp/golang-lru/simplelru"
)

// SOCollisionEventGenerator is the struct responsible to create the SO symbols collisions derived event.
// To do so, it uses multiple caches to reduce performance and chances for failure.
type SOCollisionEventGenerator struct {
	collisionEventSkeleton EventSkeleton
	soLoader               shared_objects.ISOExportSymbolsLoader
	processesSOsCache      processesLoadedObjectsCache
	collisionsCache        sharedObjectsCollisionsCache
}

func InitSOCollisionsEventGenerator(eSkel EventSkeleton, loader shared_objects.ISOExportSymbolsLoader) SOCollisionEventGenerator {
	lruCallback := simplelru.EvictCallback(func(key interface{}, value interface{}) {})
	processLoadedObjectsLRU, _ := simplelru.NewLRU(1024, lruCallback)
	objectCollisionsLRU, _ := simplelru.NewLRU(1024, lruCallback)
	return SOCollisionEventGenerator{
		soLoader:               loader,
		processesSOsCache:      processesLoadedObjectsCache{processLoadedObjectsLRU},
		collisionsCache:        sharedObjectsCollisionsCache{objectCollisionsLRU},
		collisionEventSkeleton: eSkel,
	}
}

// GenerateEvents generate an event for collisions between symbols exported by shared objects loaded to the same
// process.
// The event is triggered by the loading of a shared object, and an event will be created for each shared object
// which has collisions with the newly loaded one.
func (soColGen *SOCollisionEventGenerator) GenerateEvents(event trace.Event) ([]trace.Event, bool, error) {
	switch event.EventName {
	case "shared_object_loaded":
		return soColGen.handleSOLoaded(event)
	case "sched_process_exec":
		return soColGen.handleExec(event)
	default:
		return nil, false, fmt.Errorf("received unexpected event - \"%s\"", event.EventName)
	}
}

// handleSOLoaded check when a shared object is loaded into a process if some of its exported symbols collide with
// previously loaded shared object.
// An event will be created for each SO it has collisions with.
// The main efficiency features it uses is caching examined SOs symbols and collision check results.
// The hope is that after few processes are executed, all major libraries in the system will be cached already
// and most libraries combinations collisions check results will be cached too.
func (soColGen *SOCollisionEventGenerator) handleSOLoaded(event trace.Event) ([]trace.Event, bool, error) {
	loadingObjectInfo, err := getSharedObjectExInfo(event)
	if err != nil {
		return []trace.Event{}, false, err
	}

	processLoadedObjects, ok := soColGen.processesSOsCache.GetProcessLoadedObjects(event.HostProcessID)
	if !ok {
		processLoadedObjects = []shared_objects.SoExaminationInfo{}
	}
	newProcessLoadedObjects := append(processLoadedObjects, loadingObjectInfo)
	soColGen.processesSOsCache.SetProcessLoadedObjects(event.HostProcessID, newProcessLoadedObjects)

	// Exported symbols will be updated if needed in the findSOCollisions method
	loadingObject := SoInstance{SoExaminationInfo: loadingObjectInfo}

	var collisionEvents []trace.Event
	for _, lsoInfo := range processLoadedObjects {
		collisions, err := soColGen.findSOCollisions(&loadingObject, lsoInfo)
		if err != nil {
			return nil, false, err
		}
		if len(collisions) > 0 {
			collisionEvents = append(collisionEvents, soColGen.buildSOCollisionsEvent(event, loadingObjectInfo, lsoInfo, collisions))
		}
	}

	return collisionEvents, true, nil
}

// handleExec delete saved process loaded objects in case of execve, because entire memory is overwritten in this case
func (soColGen *SOCollisionEventGenerator) handleExec(event trace.Event) ([]trace.Event, bool, error) {
	soColGen.processesSOsCache.SetProcessLoadedObjects(event.HostProcessID, []shared_objects.SoExaminationInfo{})
	return nil, false, nil
}

// findSOCollisions check for collisions between new SO loaded to existing one in the most efficient way possible.
// It updates the given SO if symbols are missing.
func (soColGen *SOCollisionEventGenerator) findSOCollisions(so *SoInstance, loadedSO shared_objects.SoExaminationInfo) ([]string, error) {
	var err error
	collisions, ok := soColGen.collisionsCache.GetCollision(so.Id, loadedSO.Id)
	if !ok {
		if so.ExportedSymbols == nil {
			so.ExportedSymbols, err = soColGen.soLoader.GetSOExSymbols(so.SoExaminationInfo)
			if err != nil {
				return nil, err
			}
		}
		lsoSyms, err := soColGen.soLoader.GetSOExSymbols(loadedSO)
		if err != nil {
			return nil, err
		}
		lso := SoInstance{SoExaminationInfo: loadedSO, ExportedSymbols: lsoSyms}
		collisions = so.GetCollisions(lso)
		soColGen.collisionsCache.AddCollisions(so.Id, loadedSO.Id, collisions)
	}
	return collisions, nil
}

func (soColGen *SOCollisionEventGenerator) buildSOCollisionsEvent(loadEvent trace.Event, loadingObject shared_objects.SoExaminationInfo, collidedObject shared_objects.SoExaminationInfo, collidedSymbols []string) trace.Event {
	de := loadEvent
	de.EventName = soColGen.collisionEventSkeleton.Name
	de.EventID = soColGen.collisionEventSkeleton.ID
	de.ReturnValue = 0
	de.StackAddresses = make([]uint64, 1)
	de.Args = []trace.Argument{
		{ArgMeta: soColGen.collisionEventSkeleton.Params[0], Value: loadingObject.Path},
		{ArgMeta: soColGen.collisionEventSkeleton.Params[1], Value: collidedObject.Path},
		{ArgMeta: soColGen.collisionEventSkeleton.Params[2], Value: collidedSymbols},
	}
	return de
}

// getSharedObjectExInfo extract from SO loading event the information available about the SO
func getSharedObjectExInfo(event trace.Event) (shared_objects.SoExaminationInfo, error) {
	var objID shared_objects.SoExaminationInfo
	loadedObjectInode, err := parsing.GetEventArgUint64Val(&event, "inode")
	if err != nil {
		return objID, err
	}
	loadedObjectDevice, err := parsing.GetEventArgUint32Val(&event, "dev")
	if err != nil {
		return objID, err
	}
	loadedObjectCtime, err := parsing.GetEventArgUint64Val(&event, "ctime")
	if err != nil {
		return objID, err
	}
	loadedObjectPath, err := parsing.GetEventArgStringVal(&event, "pathname")
	if err != nil {
		return objID, err
	}
	objID = shared_objects.SoExaminationInfo{
		Id: shared_objects.SharedObjectIdentification{
			Inode:  loadedObjectInode,
			Device: loadedObjectDevice,
			Ctime:  loadedObjectCtime},
		Path:    loadedObjectPath,
		MountNS: event.MountNS,
	}
	return objID, nil
}

// processesLoadedObjectsCache is a cache for shared objects loaded to a process
type processesLoadedObjectsCache struct {
	cache *simplelru.LRU
}

// GetProcessLoadedObjects get the shared SOs loaded to the process, and if the process existed in the cache.
func (pcache *processesLoadedObjectsCache) GetProcessLoadedObjects(pid int) ([]shared_objects.SoExaminationInfo, bool) {
	var loadedObjects []shared_objects.SoExaminationInfo
	loadedObjectsIface, ok := pcache.cache.Get(pid)
	if ok {
		loadedObjects = loadedObjectsIface.([]shared_objects.SoExaminationInfo)
		return loadedObjects, true
	} else {
		return loadedObjects, false
	}
}

func (pcache *processesLoadedObjectsCache) SetProcessLoadedObjects(pid int, loadedObjects []shared_objects.SoExaminationInfo) {
	pcache.cache.Add(pid, loadedObjects)
}

// sharedObjectsCollisionsCache is a cache for collision checks performed already
// The results are saved per SO, which means that each collision is saved twice (because in each collision there are
// 2 SOs which collide)
type sharedObjectsCollisionsCache struct {
	cache *simplelru.LRU
}

// AddCollisions add the collisions between 2 shared objects to the cache.
func (socCache sharedObjectsCollisionsCache) AddCollisions(obj1 shared_objects.SharedObjectIdentification,
	obj2 shared_objects.SharedObjectIdentification,
	collisions []string) {
	socCache.addObjCollisions(obj1, obj2, collisions)
	socCache.addObjCollisions(obj2, obj1, collisions)
}

// GetCollision return the symbols collided between 2 shared objects from the cache if exist.
// If the the collisions are cached for one object, will update it in the seconde object cache.
// Return bool indication if the collision existed in the cache.
func (socCache sharedObjectsCollisionsCache) GetCollision(obj1 shared_objects.SharedObjectIdentification,
	obj2 shared_objects.SharedObjectIdentification) ([]string, bool) {
	obj1Collisions, ok := socCache.getObjCollisions(obj1)
	if ok {
		collisions, ok := obj1Collisions[obj2]
		if ok {
			socCache.addObjCollisions(obj2, obj1, collisions)
			return collisions, true
		}
	}
	obj2Collisions, ok := socCache.getObjCollisions(obj2)
	if ok {
		collisions, ok := obj2Collisions[obj1]
		if ok {
			socCache.addObjCollisions(obj1, obj2, collisions)
			return collisions, true
		}
	}
	return nil, false
}

// Get from the cache the collisions check result of the object with other shared objects.
// Return the collisions per other shared objects, and if the given shared object was monitored in the cache.
func (socCache sharedObjectsCollisionsCache) getObjCollisions(objID shared_objects.SharedObjectIdentification) (
	map[shared_objects.SharedObjectIdentification][]string, bool) {
	var collisions map[shared_objects.SharedObjectIdentification][]string
	collisionsIface, ok := socCache.cache.Get(objID)
	if ok {
		collisions = collisionsIface.(map[shared_objects.SharedObjectIdentification][]string)
		return collisions, true
	} else {
		return collisions, false
	}
}

func (socCache sharedObjectsCollisionsCache) setObjCollisions(objID shared_objects.SharedObjectIdentification,
	collisions map[shared_objects.SharedObjectIdentification][]string) {
	socCache.cache.Add(objID, collisions)
}

// addObjCollisions add to cache of one shared object collisions the collision with a second shared object.
func (socCache sharedObjectsCollisionsCache) addObjCollisions(objID shared_objects.SharedObjectIdentification,
	collidedObjID shared_objects.SharedObjectIdentification,
	collisions []string) {
	var objCollisions map[shared_objects.SharedObjectIdentification][]string
	collisionsIface, ok := socCache.cache.Get(objID)
	if ok {
		objCollisions = collisionsIface.(map[shared_objects.SharedObjectIdentification][]string)
		objCollisions[collidedObjID] = collisions
	} else {
		objCollisions = make(map[shared_objects.SharedObjectIdentification][]string)
		socCache.setObjCollisions(objID, objCollisions)
	}
	objCollisions[collidedObjID] = collisions
}

// SoInstance is the whole information collected on an SO
type SoInstance struct {
	shared_objects.SoExaminationInfo
	ExportedSymbols map[string]bool
}

func (so *SoInstance) ContainsSymbol(sym string) bool {
	_, ok := so.ExportedSymbols[sym]
	return ok
}

func (so *SoInstance) GetSymbols() []string {
	symbols := make([]string, len(so.ExportedSymbols))
	i := 0
	for sym := range so.ExportedSymbols {
		symbols[i] = sym
		i += 1
	}
	return symbols
}

func (so *SoInstance) GetCollisions(obj SoInstance) []string {
	var collidedSymbols []string
	for _, sym := range so.GetSymbols() {
		if obj.ContainsSymbol(sym) {
			collidedSymbols = append(collidedSymbols, sym)
		}
	}
	return collidedSymbols
}
