package sharedobjs

import (
	"debug/elf"
	"errors"
	"strings"

	"github.com/hashicorp/golang-lru/simplelru"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
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

func (soLoader *HostSymbolsLoader) GetLocalSymbols(soInfo ObjInfo) (map[string]bool, error) {
	syms, err := soLoader.loadSOSymbols(soInfo)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return syms.Local, nil
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

func parseSymbols(symbols, dynamicSymbols []elf.Symbol) *Symbols {
	objSymbols := NewSOSymbols()
	for i := range symbols {
		sym := &symbols[i] // avoid copying the entire struct by taking its address
		// NOTE(geyslan): unique.Handle might be a better choice here - and elsewhere -
		// for deduplicating strings or avoiding retention of backing memory.
		// Issue: #4761
		if sym.Value != 0 {
			name := strings.Clone(sym.Name)
			objSymbols.Local[name] = true
		}
	}
	for i := range dynamicSymbols {
		sym := &dynamicSymbols[i] // avoid copying the entire struct by taking its address
		// NOTE(geyslan): unique.Handle might be a better choice here - and elsewhere -
		// for deduplicating strings or avoiding retention of backing memory.
		// Issue: #4761
		name := strings.Clone(sym.Name)
		if sym.Library != "" || sym.Value == 0 {
			objSymbols.Imported[name] = true
		} else {
			objSymbols.Local[name] = true
			objSymbols.Exported[name] = true
		}
	}
	return &objSymbols
}

func copyMap(source map[string]bool) map[string]bool {
	copiedMap := make(map[string]bool, len(source))
	maps.Copy(copiedMap, source)
	return copiedMap
}
