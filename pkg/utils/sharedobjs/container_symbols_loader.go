package sharedobjs

import (
	"github.com/aquasecurity/tracee/pkg/containers"
)

// ContainersSymbolsLoader is a decorator for SO loaders that resolves containers-relative paths to
// absolute host paths.
// This object operation requires the CAP_DAC_OVERRIDE to access files across the system.
type ContainersSymbolsLoader struct {
	hostLoader   DynamicSymbolsLoader
	pathResolver *containers.PathResolver
}

func InitContainersSymbolsLoader(pathResolver *containers.PathResolver, cacheSize int) *ContainersSymbolsLoader {
	return &ContainersSymbolsLoader{
		hostLoader:   InitHostSymbolsLoader(cacheSize),
		pathResolver: pathResolver,
	}
}

func (cLoader *ContainersSymbolsLoader) GetDynamicSymbols(soInfo ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.ResolveAbsolutePath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, err
	}
	return cLoader.hostLoader.GetDynamicSymbols(soInfo)
}

func (cLoader *ContainersSymbolsLoader) GetExportedSymbols(soInfo ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.ResolveAbsolutePath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, err
	}
	return cLoader.hostLoader.GetExportedSymbols(soInfo)
}

func (cLoader *ContainersSymbolsLoader) GetImportedSymbols(soInfo ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.ResolveAbsolutePath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, err
	}
	return cLoader.hostLoader.GetImportedSymbols(soInfo)
}
