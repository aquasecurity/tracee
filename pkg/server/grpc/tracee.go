package grpc

import (
	"context"

	"github.com/aquasecurity/tracee/pkg/version"
	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
)

type TraceeService struct {
	pb.UnimplementedTraceeServiceServer
}

func (s *TraceeService) GetVersion(ctx context.Context, in *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: version.GetVersion()}, nil
}
