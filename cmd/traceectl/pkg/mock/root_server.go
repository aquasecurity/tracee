package mock

import (
	"context"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func (s *MockServiceServer) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: ExpectedVersion}, nil
}
