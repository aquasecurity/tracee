package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/common/logger"
)

// DataStoreService implements the gRPC DataStoreService. It dispatches write
// operations to extension-provided datastore runtimes by store name.
type DataStoreService struct {
	datastores.UnimplementedDataStoreServiceServer

	// stores maps a store name to the runtime that owns it.
	stores map[string]datastores.Runtime
}

// NewDataStoreService builds a DataStoreService from one or more extension
// runtimes, indexing each runtime's stores by name.
func NewDataStoreService(runtimes ...datastores.Runtime) *DataStoreService {
	stores := make(map[string]datastores.Runtime)

	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		for _, name := range runtime.Stores() {
			if _, exists := stores[name]; exists {
				logger.Warnw("Datastore registered by multiple runtimes; keeping first", "store", name)
				continue
			}
			stores[name] = runtime
		}
	}

	return &DataStoreService{stores: stores}
}

// WriteData writes a single entry to the store's owning runtime.
func (s *DataStoreService) WriteData(_ context.Context, req *datastores.WriteDataRequest) (*datastores.WriteDataResponse, error) {
	if err := s.withRuntime(req.StoreName, func(runtime datastores.Runtime) error {
		return runtime.WriteData(req.StoreName, req.Source, req.Entry)
	}); err != nil {
		return nil, mapRuntimeError("write", req.StoreName, err)
	}

	return &datastores.WriteDataResponse{}, nil
}

// WriteBatchData writes a batch of entries to the store's owning runtime.
func (s *DataStoreService) WriteBatchData(_ context.Context, req *datastores.WriteBatchDataRequest) (*datastores.WriteBatchDataResponse, error) {
	if err := s.withRuntime(req.StoreName, func(runtime datastores.Runtime) error {
		return runtime.WriteBatchData(req.StoreName, req.Source, req.Entries)
	}); err != nil {
		return nil, mapRuntimeError("write batch", req.StoreName, err)
	}

	return &datastores.WriteBatchDataResponse{WrittenCount: int32(len(req.Entries))}, nil
}

// DeleteData deletes a single key from the store's owning runtime.
func (s *DataStoreService) DeleteData(_ context.Context, req *datastores.DeleteDataRequest) (*datastores.DeleteDataResponse, error) {
	if err := s.withRuntime(req.StoreName, func(runtime datastores.Runtime) error {
		return runtime.DeleteData(req.StoreName, req.Source, req.Key)
	}); err != nil {
		return nil, mapRuntimeError("delete", req.StoreName, err)
	}

	return &datastores.DeleteDataResponse{}, nil
}

// ClearSource clears all entries for a source from the store's owning runtime.
func (s *DataStoreService) ClearSource(_ context.Context, req *datastores.ClearSourceRequest) (*datastores.ClearSourceResponse, error) {
	if err := s.withRuntime(req.StoreName, func(runtime datastores.Runtime) error {
		return runtime.ClearSource(req.StoreName, req.Source)
	}); err != nil {
		return nil, mapRuntimeError("clear", req.StoreName, err)
	}

	return &datastores.ClearSourceResponse{}, nil
}

// ListSources returns the source identifiers held by the store's owning runtime.
func (s *DataStoreService) ListSources(_ context.Context, req *datastores.ListSourcesRequest) (*datastores.ListSourcesResponse, error) {
	runtime, err := s.runtimeForStore(req.StoreName)
	if err != nil {
		return nil, mapRuntimeError("list sources", req.StoreName, err)
	}

	sources, err := runtime.ListSources(req.StoreName)
	if err != nil {
		return nil, mapRuntimeError("list sources", req.StoreName, err)
	}

	return &datastores.ListSourcesResponse{Sources: sources}, nil
}

// runtimeForStore returns the runtime that owns storeName, or ErrRuntimeStoreNotFound.
func (s *DataStoreService) runtimeForStore(storeName string) (datastores.Runtime, error) {
	runtime, ok := s.stores[storeName]
	if !ok {
		return nil, datastores.ErrRuntimeStoreNotFound
	}

	return runtime, nil
}

// withRuntime resolves the runtime owning storeName and runs op against it.
func (s *DataStoreService) withRuntime(storeName string, op func(datastores.Runtime) error) error {
	runtime, err := s.runtimeForStore(storeName)
	if err != nil {
		return err
	}

	return op(runtime)
}

// mapRuntimeError translates a runtime/datastore error into a gRPC status code.
func mapRuntimeError(op, storeName string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, datastores.ErrRuntimeStoreNotFound):
		return status.Errorf(codes.NotFound, "datastore %q not found", storeName)
	case errors.Is(err, datastores.ErrRuntimeUnsupported):
		return status.Errorf(codes.Unimplemented, "%s on datastore %q: %v", op, storeName, err)
	case errors.Is(err, datastores.ErrStoreUnhealthy):
		return status.Errorf(codes.Unavailable, "%s on datastore %q: %v", op, storeName, err)
	case errors.Is(err, datastores.ErrInvalidArgument):
		return status.Errorf(codes.InvalidArgument, "%s on datastore %q: %v", op, storeName, err)
	case errors.Is(err, datastores.ErrNotImplemented):
		return status.Errorf(codes.Unimplemented, "%s on datastore %q: %v", op, storeName, err)
	default:
		return status.Errorf(codes.Internal, "%s on datastore %q failed: %v", op, storeName, err)
	}
}
