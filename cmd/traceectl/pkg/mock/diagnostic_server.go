package mock

import (
	"context"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

var (
	ExpectedMetrics pb.GetMetricsResponse = pb.GetMetricsResponse{EventCount: 1, EventsFiltered: 2, NetCapCount: 3,
		BPFLogsCount: 4, ErrorCount: 5, LostEvCount: 6,
		LostWrCount: 7, LostNtCapCount: 8, LostBPFLogsCount: 9}
)

func (s *MockDiagnosticServer) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	return &ExpectedMetrics, nil
}
