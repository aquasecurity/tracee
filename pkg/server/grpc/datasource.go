package grpc

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/detect"
)

type DataSourceService struct {
	pb.UnimplementedDataSourceServiceServer
	sigEngine *engine.Engine
}

// Write implements the DataSourceService Write RPC
func (s *DataSourceService) Write(ctx context.Context, req *pb.WriteDataSourceRequest) (*pb.WriteDataSourceResponse, error) {
	// try and find data source
	datasource, ok := s.sigEngine.GetDataSource(req.Namespace, req.Id)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "requested data source does not exist (namespace: %s, id: %s)", req.Namespace, req.Id)
	}

	// check if the data source implements the writing interface
	writeable, ok := datasource.(detect.WriteableDataSource)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "requested data source is not writable (namespace: %s, id: %s)", req.Namespace, req.Id)
	}

	// data source only accepts interface{} values
	key := req.Key.AsInterface()
	value := req.Value.AsInterface()

	// convert to the writable format
	data := map[interface{}]interface{}{
		key: value,
	}
	err := writeable.Write(data)
	if err != nil {
		if errors.Is(err, detect.ErrKeyNotSupported) {
			return nil, status.Errorf(codes.InvalidArgument, "given key is not supported")
		}
		if errors.Is(err, detect.ErrFailedToUnmarshal) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to unmarshal given key or value")
		}
		return nil, status.Errorf(codes.Internal, "internal error when writing to data source: %v", err)
	}

	return &pb.WriteDataSourceResponse{}, nil
}

func (s *DataSourceService) WriteStream(stream pb.DataSourceService_WriteStreamServer) error {
	var writeable detect.WriteableDataSource
	data := make(map[interface{}]interface{})

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if writeable == nil {
			// discover writable datasource from first message
			datasource, ok := s.sigEngine.GetDataSource(msg.Namespace, msg.Id)
			if !ok {
				return status.Errorf(codes.NotFound, "requested data source does not exist (namespace: %s, id: %s)", msg.Namespace, msg.Id)
			}
			writeable, ok = datasource.(detect.WriteableDataSource)
			if !ok {
				return status.Errorf(codes.Unimplemented, "requested data source is not writable (namespace: %s, id: %s)", msg.Namespace, msg.Id)
			}
		}

		key := msg.Key.AsInterface()
		value := msg.Value.AsInterface()

		data[key] = value // append stream value to written data
	}

	// after stream is done, write the data
	err := writeable.Write(data)
	if err != nil {
		if errors.Is(err, detect.ErrKeyNotSupported) {
			return status.Errorf(codes.InvalidArgument, "a given key is not supported")
		}
		if errors.Is(err, detect.ErrFailedToUnmarshal) {
			return status.Errorf(codes.InvalidArgument, "failed to unmarshal a given key or value")
		}
		return status.Errorf(codes.Internal, "internal error when writing to data source: %v", err)
	}
	return stream.SendAndClose(&pb.WriteDataSourceResponse{})
}
