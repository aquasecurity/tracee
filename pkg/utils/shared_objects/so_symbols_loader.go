package shared_objects

import (
	"debug/elf"
	"github.com/hashicorp/golang-lru/simplelru"
)

// SharedObjectExSymbolsLoader is responsible for efficient reading of shared object's exported symbols.
type SharedObjectExSymbolsLoader struct {
	soCache sharedObjectsInfoCache
}

func InitSOExSymbolsLoader(cacheSize int) *SharedObjectExSymbolsLoader {
	lruCallback := simplelru.EvictCallback(func(key interface{}, value interface{}) { return })
	sharedObjectsLRU, _ := simplelru.NewLRU(cacheSize, lruCallback)
	soCache := sharedObjectsInfoCache{sharedObjectsLRU}
	return &SharedObjectExSymbolsLoader{soCache: soCache}
}

// GetSOExSymbols try to get shared objects exported symbols from cache, and if fails read needed information.
// from ELF file.
func (soLoader *SharedObjectExSymbolsLoader) GetSOExSymbols(soInfo SoExaminationInfo) (map[string]bool, error) {
	syms, ok := soLoader.soCache.getSharedObjectSymbols(soInfo.Id)
	if ok {
		return syms, nil
	}
	syms, err := loadSharedObjectExportedSymbols(soInfo.Path)
	if err != nil {
		return nil, err
	}
	soLoader.soCache.addSharedObjectSymbols(soInfo, syms)
	return syms, nil
}

// sharedObjectsInfoCache is a cache for examined shared objects symbols, in order to reduce file access.
type sharedObjectsInfoCache struct {
	cache *simplelru.LRU
}

// Get SO instance from the cache.
// Return the SO symbols from cache and if the SO symbols were in the cache.
func (soCache *sharedObjectsInfoCache) getSharedObjectSymbols(objID SharedObjectIdentification) (map[string]bool, bool) {
	objInfoIface, ok := soCache.cache.Get(objID)
	if ok {
		objInfo := objInfoIface.(map[string]bool)
		return objInfo, true
	} else {
		return nil, false
	}
}

func (soCache *sharedObjectsInfoCache) addSharedObjectSymbols(obj SoExaminationInfo, exportedSymbols map[string]bool) {
	soCache.cache.Add(obj.Id, exportedSymbols)
}

// loadSharedObjectExportedSymbols load all exported dynamic symbols of a shared object in given path.
func loadSharedObjectExportedSymbols(path string) (map[string]bool, error) {
	loadedObject, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	exportedSymbols, err := loadedObject.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	objExportedSymbols := make(map[string]bool)
	for _, sym := range exportedSymbols {
		if sym.Library != "" || sym.Value == 0 {
			continue
		}
		objExportedSymbols[sym.Name] = true
	}
	return objExportedSymbols, nil
}
