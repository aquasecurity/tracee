package sharedobjs

import (
	"debug/elf"

	"github.com/hashicorp/golang-lru/simplelru"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// HostSymbolsLoader is responsible for efficient reading of shared object's symbols.
// The logic of the loader here is used on absolute paths, so container relative paths won't work here.
// This object operation requires the CAP_DAC_OVERRIDE to access files across the system.
type HostSymbolsLoader struct {
	loadingFunc func(path string) (*dynamicSymbols, error)
	soCache     soDynamicSymbolsCache
}

func InitHostSymbolsLoader(cacheSize int) *HostSymbolsLoader {
	lruCallback := simplelru.EvictCallback(func(key interface{}, value interface{}) {})
	sharedObjectsLRU, _ := simplelru.NewLRU(cacheSize, lruCallback)
	soCache := dynamicSymbolsLRUCache{sharedObjectsLRU}
	return &HostSymbolsLoader{
		soCache:     &soCache,
		loadingFunc: loadSharedObjectDynamicSymbols,
	}
}

// GetDynamicSymbols try to get shared objects dynamic symbols from lru, and if fails read needed information
// from ELF file.
func (soLoader *HostSymbolsLoader) GetDynamicSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	dynSyms := copyMap(syms.Imported)
	for expSym := range syms.Exported {
		dynSyms[expSym] = true
	}
	return dynSyms, nil
}

// GetExportedSymbols try to get shared objects exported symbols from lru, and if fails read needed information
// from ELF file.
// The returned map is part of a cache, so if the user wants to modify it he should copy it and modify it there.
func (soLoader *HostSymbolsLoader) GetExportedSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.Exported, nil
}

// GetImportedSymbols try to get shared objects imported symbols from lru, and if fails read needed information
// from ELF file.
// The returned map is part of a cache, so if the user wants to modify it he should copy it and modify it there.
func (soLoader *HostSymbolsLoader) GetImportedSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.Imported, nil
}

func (soLoader *HostSymbolsLoader) loadSOSymbols(soInfo ObjInfo) (*dynamicSymbols, error) {
	syms, ok := soLoader.soCache.Get(soInfo.Id)
	if ok {
		return syms, nil
	}
	syms, err := soLoader.loadingFunc(soInfo.Path)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	soLoader.soCache.Add(soInfo, syms)
	return syms, nil
}

type soDynamicSymbolsCache interface {
	Get(ObjID) (*dynamicSymbols, bool)
	Add(obj ObjInfo, dynamicSymbols *dynamicSymbols)
}

// dynamicSymbolsLRUCache is a lru for examined shared objects symbols, in order to reduce file access.
type dynamicSymbolsLRUCache struct {
	lru *simplelru.LRU
}

// Get SO instance from the lru.
// Return the SO symbols from lru and if the SO symbols were in the lru.
func (soCache *dynamicSymbolsLRUCache) Get(objID ObjID) (*dynamicSymbols, bool) {
	objInfoIface, ok := soCache.lru.Get(objID)
	if ok {
		objInfo := objInfoIface.(*dynamicSymbols)
		return objInfo, true
	} else {
		return nil, false
	}
}

func (soCache *dynamicSymbolsLRUCache) Add(obj ObjInfo, dynamicSymbols *dynamicSymbols) {
	soCache.lru.Add(obj.Id, dynamicSymbols)
}

// loadSharedObjectDynamicSymbols load all dynamic symbols of a shared object file in given path.
func loadSharedObjectDynamicSymbols(path string) (*dynamicSymbols, error) {
	var loadedObject *elf.File

	err := capabilities.GetInstance().Required(func() error {
		var e error
		loadedObject, e = elf.Open(path)
		return e
	})
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	defer func() {
		if err := loadedObject.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	dynamicSymbols, err := loadedObject.DynamicSymbols()
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return parseDynamicSymbols(dynamicSymbols), nil
}

func parseDynamicSymbols(dynamicSymbols []elf.Symbol) *dynamicSymbols {
	objSymbols := NewSOSymbols()
	for _, sym := range dynamicSymbols {
		if sym.Library != "" || sym.Value == 0 {
			objSymbols.Imported[sym.Name] = true
		} else {
			objSymbols.Exported[sym.Name] = true
		}
	}
	return &objSymbols
}

func copyMap(source map[string]bool) map[string]bool {
	copiedMap := make(map[string]bool, len(source))
	maps.Copy(copiedMap, source)
	return copiedMap
}
