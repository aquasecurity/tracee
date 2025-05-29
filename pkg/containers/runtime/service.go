package runtime

import (
	"context"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type Service struct {
	sockets   Sockets
	enrichers map[RuntimeId]ContainerEnricher
}

// RuntimeInfoService initializes a service which can register enrichers for container runtimes
func NewService(sockets Sockets) Service {
	return Service{
		enrichers: make(map[RuntimeId]ContainerEnricher),
		sockets:   sockets,
	}
}

// Register associates some ContainerEnricher with a runtime, the service can then use it for relevant queries
func (e *Service) Register(rtime RuntimeId, enricherBuilder func(socket string) (ContainerEnricher, error)) error {
	if !e.sockets.Supports(rtime) {
		return errfmt.Errorf("error registering enricher: unsupported runtime %s", rtime.String())
	}
	socket := e.sockets.Socket(rtime)
	enricher, err := enricherBuilder(socket)
	if err != nil {
		return errfmt.WrapError(err)
	}
	e.enrichers[rtime] = enricher
	return nil
}

// Get calls the inner enricher's Get, based on the containerRuntime parameter if a relevant enricher was registered
// If an unknown runtime is received, enrichment will be attempted through all registered enrichers
func (e *Service) Get(ctx context.Context, containerId string, containerRuntime RuntimeId) (EnrichResult, error) {
	if containerRuntime == Unknown {
		return e.getFromUnknownRuntime(ctx, containerId)
	}

	return e.getFromKnownRuntime(ctx, containerId, containerRuntime)
}

// standard case when we can query the known runtime from the get go
func (e *Service) getFromKnownRuntime(ctx context.Context, containerId string, containerRuntime RuntimeId) (EnrichResult, error) {
	enricher := e.enrichers[containerRuntime]
	if enricher != nil {
		return enricher.Get(ctx, containerId)
	}
	return EnrichResult{}, errfmt.Errorf("unsupported runtime %s", containerRuntime.String())
}

// in case where we don't know the container's runtime, we query through all the registered enrichers
func (e *Service) getFromUnknownRuntime(ctx context.Context, containerId string) (EnrichResult, error) {
	for _, enricher := range e.enrichers {
		metadata, err := enricher.Get(ctx, containerId)

		if err == nil {
			return metadata, nil
		}
	}

	return EnrichResult{}, errfmt.Errorf("no runtime found for container")
}
