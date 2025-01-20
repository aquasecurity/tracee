package client

import (
	"context"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func (tc *Server) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	return tc.diagnosticClient.GetMetrics(ctx, req)
}
