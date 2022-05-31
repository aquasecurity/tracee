package shared_objects

import (
	"github.com/aquasecurity/tracee/pkg/containers"
)

// ContainersPathSOSymsLoaderDecorator is a decorator for SO loaders that resolves containers-relative paths to
// absolute host paths.
type ContainersPathSOSymsLoaderDecorator struct {
	hostLoader   ISOExportSymbolsLoader
	pathResolver *containers.ContainersPathResolver
}

func InitContainersSOSymbolsLoader(pathResolver *containers.ContainersPathResolver) ContainersPathSOSymsLoaderDecorator {
	return ContainersPathSOSymsLoaderDecorator{
		hostLoader:   InitSOExSymbolsLoader(1024),
		pathResolver: pathResolver,
	}
}

func (cloader ContainersPathSOSymsLoaderDecorator) GetSOExSymbols(soInfo SoExaminationInfo) (map[string]bool, error) {
	var err error
	soInfo.Path, err = cloader.pathResolver.ResolveAbsolutePath(soInfo.Path, soInfo.MountNS)
	if err != nil {
		return nil, err
	}
	return cloader.hostLoader.GetSOExSymbols(soInfo)
}
