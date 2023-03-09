package containers

import (
	"context"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type runtimeInfoService struct {
	sockets   runtime.Sockets
	enrichers map[runtime.RuntimeId]runtime.ContainerEnricher
}

// RuntimeInfoService initializes a service which can register enrichers for container runtimes
func RuntimeInfoService(sockets runtime.Sockets) runtimeInfoService {
	return runtimeInfoService{
		enrichers: make(map[runtime.RuntimeId]runtime.ContainerEnricher),
		sockets:   sockets,
	}
}

// Register associates some ContainerEnricher with a runtime, the service can then use it for relevant queries
func (e *runtimeInfoService) Register(runtime runtime.RuntimeId, enricherBuilder func(socket string) (runtime.ContainerEnricher, error)) error {
	if !e.sockets.Supports(runtime) {
		return errfmt.Errorf("error registering enricher: unsupported runtime %s", runtime.String())
	}
	socket := e.sockets.Socket(runtime)
	enricher, err := enricherBuilder(socket)
	if err != nil {
		return errfmt.WrapError(err)
	}
	e.enrichers[runtime] = enricher
	return nil
}

// Get calls the inner enricher's Get, based on the containerRuntime parameter if a relevant enricher was registered
// If an unknown runtime is received, enrichment will be attempted through all registered enrichers
func (e *runtimeInfoService) Get(containerId string, containerRuntime runtime.RuntimeId, ctx context.Context) (runtime.ContainerMetadata, error) {
	if containerRuntime == runtime.Unknown {
		return e.getFromUnknownRuntime(containerId, ctx)
	}

	return e.getFromKnownRuntime(containerId, containerRuntime, ctx)
}

// standard case when we can query the known runtime from the get go
func (e *runtimeInfoService) getFromKnownRuntime(containerId string, containerRuntime runtime.RuntimeId, ctx context.Context) (runtime.ContainerMetadata, error) {
	enricher := e.enrichers[containerRuntime]
	if enricher != nil {
		return enricher.Get(containerId, ctx)
	}
	return runtime.ContainerMetadata{}, errfmt.Errorf("unsupported runtime")
}

// in case where we don't know the container's runtime, we query through all the registered enrichers
func (e *runtimeInfoService) getFromUnknownRuntime(containerId string, ctx context.Context) (runtime.ContainerMetadata, error) {
	for _, enricher := range e.enrichers {
		metadata, err := enricher.Get(containerId, ctx)

		if err == nil {
			return metadata, nil
		}
	}

	return runtime.ContainerMetadata{}, errfmt.Errorf("no runtime found for container")
}
