package sharedobjs

import (
	"debug/elf"
	"errors"

	"github.com/hashicorp/golang-lru/simplelru"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/intern"
	"github.com/aquasecurity/tracee/common/logger"
)

// HostSymbolsLoader is responsible for efficient reading of shared object's symbols.
// The logic of the loader here is used on absolute paths, so container relative paths won't work here.
// This object operation requires the CAP_DAC_OVERRIDE to access files across the system.
type HostSymbolsLoader struct {
	loadingFunc func(path string) (*Symbols, error)
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

// GetDynamicSymbols returns the union of imported and exported symbols of the
// shared object. The returned map is freshly allocated on every call and is
// safe for the caller to mutate.
func (soLoader *HostSymbolsLoader) GetDynamicSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.View(CategoryDynamic), nil
}

// GetExportedSymbols returns the exported symbols of the shared object.
//
// The returned map is freshly built per call from the cached internal store;
// callers may freely retain or mutate it.
func (soLoader *HostSymbolsLoader) GetExportedSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.View(CategoryExported), nil
}

// GetImportedSymbols returns the imported symbols of the shared object.
//
// The returned map is freshly built per call from the cached internal store;
// callers may freely retain or mutate it.
func (soLoader *HostSymbolsLoader) GetImportedSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.View(CategoryImported), nil
}

// GetLocalSymbols returns the local symbols of the shared object.
//
// The returned map is freshly built per call from the cached internal store;
// callers may freely retain or mutate it.
func (soLoader *HostSymbolsLoader) GetLocalSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.View(CategoryLocal), nil
}

func (soLoader *HostSymbolsLoader) loadSOSymbols(soInfo ObjInfo) (*Symbols, error) {
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
	Get(ObjID) (*Symbols, bool)
	Add(obj ObjInfo, dynamicSymbols *Symbols)
}

// dynamicSymbolsLRUCache is a lru for examined shared objects symbols, in order to reduce file access.
type dynamicSymbolsLRUCache struct {
	lru *simplelru.LRU
}

// Get SO instance from the lru.
// Return the SO symbols from lru and if the SO symbols were in the lru.
func (soCache *dynamicSymbolsLRUCache) Get(objID ObjID) (*Symbols, bool) {
	objInfoIface, ok := soCache.lru.Get(objID)
	if ok {
		if objInfo, ok := objInfoIface.(*Symbols); ok {
			return objInfo, true
		}
	}

	return nil, false
}

func (soCache *dynamicSymbolsLRUCache) Add(obj ObjInfo, dynamicSymbols *Symbols) {
	soCache.lru.Add(obj.Id, dynamicSymbols)
}

// loadSharedObjectDynamicSymbols loads all dynamic symbols of a shared object file in given path.
func loadSharedObjectDynamicSymbols(path string) (*Symbols, error) {
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

	symbols, err1 := loadedObject.Symbols()
	dynamicSymbols, err2 := loadedObject.DynamicSymbols()
	if err1 != nil && err2 != nil {
		return nil, errfmt.Errorf("binary %s has no symbols: %v, %v", path, err1, err2)
	}

	return parseSymbols(symbols, dynamicSymbols), nil
}

// parseSymbols classifies ELF symbols into a compact Symbols store.
//
// All names are canonicalized via intern.String (Geyslan, issue #4761) so
// identical symbols across SOs share one backing buffer, and a symbol that
// belongs to more than one category (e.g. Local + Exported) occupies a single
// map entry whose category bits are OR'd together.
func parseSymbols(symbols, dynamicSymbols []elf.Symbol) *Symbols {
	// Upper bound: every symbol contributes at most one map entry. Pre-sizing
	// to the sum keeps map growth out of the parse hot path even when there is
	// no overlap between the two input slices.
	objSymbols := newSymbolsWithCapacity(len(symbols) + len(dynamicSymbols))
	for i := range symbols {
		sym := &symbols[i] // avoid copying the entire struct by taking its address
		if sym.Value != 0 {
			objSymbols.add(intern.String(sym.Name), CategoryLocal)
		}
	}
	for i := range dynamicSymbols {
		sym := &dynamicSymbols[i] // avoid copying the entire struct by taking its address
		name := intern.String(sym.Name)
		if sym.Library != "" || sym.Value == 0 {
			objSymbols.add(name, CategoryImported)
		} else {
			objSymbols.add(name, CategoryLocal|CategoryExported)
		}
	}
	return objSymbols
}
