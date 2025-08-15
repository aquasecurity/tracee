package containers

import (
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/sharedobjs"
)

// ContainersSymbolsLoader is a decorator for SO loaders that resolves containers-relative paths to
// absolute host paths.
// This object operation requires the CAP_DAC_OVERRIDE to access files across the system.
type ContainersSymbolsLoader struct {
	hostLoader   sharedobjs.DynamicSymbolsLoader
	pathResolver *ContainerPathResolver
}

func InitContainersSymbolsLoader(pathResolver *ContainerPathResolver, cacheSize int) *ContainersSymbolsLoader {
	return &ContainersSymbolsLoader{
		hostLoader:   sharedobjs.InitHostSymbolsLoader(cacheSize),
		pathResolver: pathResolver,
	}
}

func (cLoader *ContainersSymbolsLoader) GetDynamicSymbols(soInfo sharedobjs.ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.GetHostAbsPath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return cLoader.hostLoader.GetDynamicSymbols(soInfo)
}

func (cLoader *ContainersSymbolsLoader) GetExportedSymbols(soInfo sharedobjs.ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.GetHostAbsPath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return cLoader.hostLoader.GetExportedSymbols(soInfo)
}

func (cLoader *ContainersSymbolsLoader) GetImportedSymbols(soInfo sharedobjs.ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.GetHostAbsPath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return cLoader.hostLoader.GetImportedSymbols(soInfo)
}

func (cLoader *ContainersSymbolsLoader) GetLocalSymbols(soInfo sharedobjs.ObjInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cLoader.pathResolver.GetHostAbsPath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	return cLoader.hostLoader.GetLocalSymbols(soInfo)
}
