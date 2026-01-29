package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

type DataStoreService struct {
	dsapi.UnimplementedDataStoreServiceServer
	registry dsapi.Registry
}

// WriteData implements the DataStoreService WriteData RPC
func (s *DataStoreService) WriteData(ctx context.Context, req *dsapi.WriteDataRequest) (*dsapi.WriteDataResponse, error) {
	if req.StoreName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "store name is required")
	}
	if req.Source == "" {
		return nil, status.Errorf(codes.InvalidArgument, "source is required")
	}
	if req.Entry == nil {
		return nil, status.Errorf(codes.InvalidArgument, "entry is required")
	}

	// Get the datastore from registry
	store, err := s.registry.GetCustom(req.StoreName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "datastore '%s' not found: %v", req.StoreName, err)
	}

	// Type assert to WritableStore
	writable, ok := store.(dsapi.WritableStore)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "datastore '%s' is not writable", req.StoreName)
	}

	// Write the entry
	err = writable.Write(req.Source, req.Entry)
	if err != nil {
		if errors.Is(err, dsapi.ErrInvalidArgument) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid argument: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to write data: %v", err)
	}

	return &dsapi.WriteDataResponse{}, nil
}

// WriteBatchData implements the DataStoreService WriteBatchData RPC
func (s *DataStoreService) WriteBatchData(ctx context.Context, req *dsapi.WriteBatchDataRequest) (*dsapi.WriteBatchDataResponse, error) {
	if req.StoreName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "store name is required")
	}
	if req.Source == "" {
		return nil, status.Errorf(codes.InvalidArgument, "source is required")
	}
	if len(req.Entries) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "entries cannot be empty")
	}

	// Get the datastore from registry
	store, err := s.registry.GetCustom(req.StoreName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "datastore '%s' not found: %v", req.StoreName, err)
	}

	// Type assert to WritableStore
	writable, ok := store.(dsapi.WritableStore)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "datastore '%s' is not writable", req.StoreName)
	}

	// Write batch entries
	err = writable.WriteBatch(req.Source, req.Entries)
	if err != nil {
		if errors.Is(err, dsapi.ErrInvalidArgument) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid argument: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to write batch data: %v", err)
	}

	return &dsapi.WriteBatchDataResponse{
		WrittenCount: int32(len(req.Entries)),
	}, nil
}

// DeleteData implements the DataStoreService DeleteData RPC
func (s *DataStoreService) DeleteData(ctx context.Context, req *dsapi.DeleteDataRequest) (*dsapi.DeleteDataResponse, error) {
	if req.StoreName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "store_name is required")
	}
	if req.Source == "" {
		return nil, status.Errorf(codes.InvalidArgument, "source is required")
	}
	if req.Key == nil {
		return nil, status.Errorf(codes.InvalidArgument, "key is required")
	}

	// Get the datastore from registry
	store, err := s.registry.GetCustom(req.StoreName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "datastore '%s' not found: %v", req.StoreName, err)
	}

	// Type assert to WritableStore
	writable, ok := store.(dsapi.WritableStore)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "datastore '%s' is not writable", req.StoreName)
	}

	// Delete the entry
	err = writable.Delete(req.Source, req.Key)
	if err != nil {
		if errors.Is(err, dsapi.ErrInvalidArgument) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid argument: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to delete data: %v", err)
	}

	return &dsapi.DeleteDataResponse{}, nil
}

// ClearSource implements the DataStoreService ClearSource RPC
func (s *DataStoreService) ClearSource(ctx context.Context, req *dsapi.ClearSourceRequest) (*dsapi.ClearSourceResponse, error) {
	if req.StoreName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "store name is required")
	}
	if req.Source == "" {
		return nil, status.Errorf(codes.InvalidArgument, "source is required")
	}

	// Get the datastore from registry
	store, err := s.registry.GetCustom(req.StoreName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "datastore '%s' not found: %v", req.StoreName, err)
	}

	// Type assert to WritableStore
	writable, ok := store.(dsapi.WritableStore)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "datastore '%s' is not writable", req.StoreName)
	}

	// Clear the source
	err = writable.Clear(req.Source)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to clear source: %v", err)
	}

	// TODO: implement deleted count return
	return &dsapi.ClearSourceResponse{
		DeletedCount: 0,
	}, nil
}

// ListSources implements the DataStoreService ListSources RPC
func (s *DataStoreService) ListSources(ctx context.Context, req *dsapi.ListSourcesRequest) (*dsapi.ListSourcesResponse, error) {
	if req.StoreName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "store name is required")
	}

	// Get the datastore from registry
	store, err := s.registry.GetCustom(req.StoreName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "datastore '%s' not found: %v", req.StoreName, err)
	}

	// Type assert to WritableStore
	writable, ok := store.(dsapi.WritableStore)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "datastore '%s' is not writable", req.StoreName)
	}

	// List sources
	sources, err := writable.ListSources()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list sources: %v", err)
	}

	return &dsapi.ListSourcesResponse{
		Sources: sources,
	}, nil
}
