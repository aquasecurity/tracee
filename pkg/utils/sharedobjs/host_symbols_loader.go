package sharedobjs

import (
	"debug/elf"
	"errors"

	"github.com/hashicorp/golang-lru/simplelru"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// HostSymbolsLoader is responsible for efficient reading of shared object's symbols.
// The logic of the loader here is used on absolute paths, so container relative paths won't work here.
// This object operation requires the CAP_DAC_OVERRIDE to access files across the system.
type HostSymbolsLoader struct {
	loadingFunc func(path string) (*DynamicSymbols, error)
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
func (soLoader *HostSymbolsLoader) GetDynamicSymbols(soInfo ObjInfo) (map[string]struct{}, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	dynSyms := copyMap(syms.Imported)
	for expSym := range syms.Exported {
		safeExpSym := string([]byte(expSym)) // force copy of the string to avoid memory retention
		dynSyms[safeExpSym] = struct{}{}
	}
	return dynSyms, nil
}

// GetExportedSymbols try to get shared objects exported symbols from lru, and if fails read needed information
// from ELF file.
// The returned map is part of a cache, so if the user wants to modify it he should copy it and modify it there.
func (soLoader *HostSymbolsLoader) GetExportedSymbols(soInfo ObjInfo) (map[string]struct{}, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.Exported, nil
}

func (soLoader *HostSymbolsLoader) GetAllExportedSymbols() []string {
	syms := []string{}
	for _, so := range soLoader.soCache.(*dynamicSymbolsLRUCache).lru.Keys() {
		if objInfo, ok := so.(*DynamicSymbols); ok {
			for expSym := range objInfo.Exported {
				safeExpSym := string([]byte(expSym)) // force copy of the string to avoid memory retention
				syms = append(syms, safeExpSym)
			}
		}
	}
	return syms
}

func (soLoader *HostSymbolsLoader) GetAllImportedSymbols() []string {
	syms := []string{}
	for _, so := range soLoader.soCache.(*dynamicSymbolsLRUCache).lru.Keys() {
		if objInfo, ok := so.(*DynamicSymbols); ok {
			for impSym := range objInfo.Imported {
				safeImpSym := string([]byte(impSym)) // force copy of the string to avoid memory retention
				syms = append(syms, safeImpSym)
			}
		}
	}
	return syms
}

// GetImportedSymbols try to get shared objects imported symbols from lru, and if fails read needed information
// from ELF file.
// The returned map is part of a cache, so if the user wants to modify it he should copy it and modify it there.
func (soLoader *HostSymbolsLoader) GetImportedSymbols(soInfo ObjInfo) (map[string]struct{}, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.Imported, nil
}

func (soLoader *HostSymbolsLoader) loadSOSymbols(soInfo ObjInfo) (*DynamicSymbols, error) {
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
	Get(ObjID) (*DynamicSymbols, bool)
	Add(obj ObjInfo, dynamicSymbols *DynamicSymbols)
}

// dynamicSymbolsLRUCache is a lru for examined shared objects symbols, in order to reduce file access.
type dynamicSymbolsLRUCache struct {
	lru *simplelru.LRU
}

// Get SO instance from the lru.
// Return the SO symbols from lru and if the SO symbols were in the lru.
func (soCache *dynamicSymbolsLRUCache) Get(objID ObjID) (*DynamicSymbols, bool) {
	objInfoIface, ok := soCache.lru.Get(objID)
	if ok {
		if objInfo, ok := objInfoIface.(*DynamicSymbols); ok {
			return objInfo, true
		}
	}

	return nil, false
}

func (soCache *dynamicSymbolsLRUCache) Add(obj ObjInfo, dynamicSymbols *DynamicSymbols) {
	soCache.lru.Add(obj.Id, dynamicSymbols)
}

// loadSharedObjectDynamicSymbols loads all dynamic symbols of a shared object file in given path.
func loadSharedObjectDynamicSymbols(path string) (*DynamicSymbols, error) {
	var err error
	var loadedObject *elf.File

	// cap.SYS_PTRACE is needed here. Instead of raising privileges, since this
	// is called too frequently, if the needed event is being traced, the needed
	// capabilities are added to the Base ring and are always set as effective.
	//
	// (Note: To change this behavior we need a privileged process/server)

	loadedObject, err = elf.Open(path)
	if err != nil {
		// We need to distinguish between errors from ELF file parsing and unsupported types
		var formatError *elf.FormatError
		if errors.As(err, &formatError) {
			return nil, InitUnsupportedFileError(err)
		}
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

func parseDynamicSymbols(dynamicSymbols []elf.Symbol) *DynamicSymbols {
	objSymbols := NewSOSymbols()
	for i := range dynamicSymbols {
		sym := &dynamicSymbols[i]        // avoid copying the whole struct
		name := string([]byte(sym.Name)) // force copy of the string to avoid memory retention
		if sym.Library != "" || sym.Value == 0 {
			objSymbols.Imported[name] = struct{}{}
		} else {
			objSymbols.Exported[name] = struct{}{}
		}
	}
	return &objSymbols
}

func copyMap(source map[string]struct{}) map[string]struct{} {
	copiedMap := make(map[string]struct{}, len(source))

	for key := range source {
		safeKey := string([]byte(key)) // force copy of the string to avoid memory retention
		copiedMap[safeKey] = struct{}{}
	}

	return copiedMap
}
