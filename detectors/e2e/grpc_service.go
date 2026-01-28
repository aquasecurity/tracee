//go:build e2e

package e2e

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// dataStoreServiceServer implements the DataStoreService gRPC by delegating to the registry.
type dataStoreServiceServer struct {
	dsapi.UnimplementedDataStoreServiceServer
	registry dsapi.Registry
}

// NewDataStoreService creates a DataStoreService gRPC server backed by the given registry.
func NewDataStoreService(reg dsapi.Registry) dsapi.DataStoreServiceServer {
	return &dataStoreServiceServer{registry: reg}
}

// RegisterE2eGrpcServices registers e2e-specific gRPC services (DataStoreService).
// Called by pkg/server/grpc/server_e2e.go when starting the gRPC server.
func RegisterE2eGrpcServices(grpcServer *grpc.Server, registry dsapi.Registry) {
	dsapi.RegisterDataStoreServiceServer(grpcServer, NewDataStoreService(registry))
}

func (s *dataStoreServiceServer) getWritable(storeName string) (dsapi.WritableStore, error) {
	store, err := s.registry.GetCustom(storeName)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "datastore %q not found: %v", storeName, err)
	}
	ws, ok := store.(dsapi.WritableStore)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "datastore %q is not writable", storeName)
	}
	return ws, nil
}

func (s *dataStoreServiceServer) WriteData(ctx context.Context, req *dsapi.WriteDataRequest) (*dsapi.WriteDataResponse, error) {
	if req == nil || req.StoreName == "" || req.Entry == nil {
		return nil, status.Error(codes.InvalidArgument, "store_name and entry are required")
	}
	ws, err := s.getWritable(req.StoreName)
	if err != nil {
		return nil, err
	}
	if err := ws.Write(req.Source, req.Entry); err != nil {
		return nil, status.Errorf(codes.Internal, "write failed: %v", err)
	}
	return &dsapi.WriteDataResponse{}, nil
}

func (s *dataStoreServiceServer) WriteBatchData(ctx context.Context, req *dsapi.WriteBatchDataRequest) (*dsapi.WriteBatchDataResponse, error) {
	if req == nil || req.StoreName == "" {
		return nil, status.Error(codes.InvalidArgument, "store_name is required")
	}
	ws, err := s.getWritable(req.StoreName)
	if err != nil {
		return nil, err
	}
	if err := ws.WriteBatch(req.Source, req.Entries); err != nil {
		return nil, status.Errorf(codes.Internal, "write batch failed: %v", err)
	}
	return &dsapi.WriteBatchDataResponse{WrittenCount: int32(len(req.Entries))}, nil
}

func (s *dataStoreServiceServer) DeleteData(ctx context.Context, req *dsapi.DeleteDataRequest) (*dsapi.DeleteDataResponse, error) {
	if req == nil || req.StoreName == "" || req.Key == nil {
		return nil, status.Error(codes.InvalidArgument, "store_name and key are required")
	}
	ws, err := s.getWritable(req.StoreName)
	if err != nil {
		return nil, err
	}
	if err := ws.Delete(req.Source, req.Key); err != nil {
		return nil, status.Errorf(codes.Internal, "delete failed: %v", err)
	}
	return &dsapi.DeleteDataResponse{}, nil
}

func (s *dataStoreServiceServer) ClearSource(ctx context.Context, req *dsapi.ClearSourceRequest) (*dsapi.ClearSourceResponse, error) {
	if req == nil || req.StoreName == "" {
		return nil, status.Error(codes.InvalidArgument, "store_name is required")
	}
	ws, err := s.getWritable(req.StoreName)
	if err != nil {
		return nil, err
	}
	if err := ws.Clear(req.Source); err != nil {
		return nil, status.Errorf(codes.Internal, "clear source failed: %v", err)
	}
	return &dsapi.ClearSourceResponse{}, nil
}

func (s *dataStoreServiceServer) ListSources(ctx context.Context, req *dsapi.ListSourcesRequest) (*dsapi.ListSourcesResponse, error) {
	if req == nil || req.StoreName == "" {
		return nil, status.Error(codes.InvalidArgument, "store_name is required")
	}
	ws, err := s.getWritable(req.StoreName)
	if err != nil {
		return nil, err
	}
	sources, err := ws.ListSources()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sources failed: %v", err)
	}
	return &dsapi.ListSourcesResponse{Sources: sources}, nil
}
