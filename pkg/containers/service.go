package containers

import (
	"context"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
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
		return fmt.Errorf("error registering enricher: unsupported runtime %s", runtime.String())
	}
	socket := e.sockets.Socket(runtime)
	enricher, err := enricherBuilder(socket)
	if err != nil {
		return err
	}
	e.enrichers[runtime] = enricher
	return nil
}

// Get calls the inner enricher's Get, based on the containerRuntime parameter if a relevant enricher was registered
func (e *runtimeInfoService) Get(conainterId string, containerRuntime runtime.RuntimeId, ctx context.Context) (runtime.ContainerMetadata, error) {
	enricher := e.enrichers[containerRuntime]
	if enricher != nil {
		return enricher.Get(conainterId, ctx)
	}
	return runtime.ContainerMetadata{}, fmt.Errorf("unsupported runtime")
}
