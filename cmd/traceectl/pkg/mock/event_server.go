package mock

import (
	"context"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func (s *MockServiceServer) GetEventDefinitions(ctx context.Context, req *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	var eventDefinition []*pb.EventDefinition
	for i := 0; i < len(req.EventNames); i++ {
		eventDefinition = append(eventDefinition, &pb.EventDefinition{Name: req.EventNames[i], Id: (int32(i))})
	}
	return &pb.GetEventDefinitionsResponse{Definitions: eventDefinition}, nil
}
func (s *MockServiceServer) DescribeEvent(ctx context.Context, req *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	return s.GetEventDefinitions(ctx, req)
}
func (s *MockServiceServer) ListEvent(ctx context.Context, req *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	return s.GetEventDefinitions(ctx, req)
}

func (s *MockServiceServer) EnableEvent(ctx context.Context, req *pb.EnableEventRequest) (*pb.EnableEventResponse, error) {
	return &pb.EnableEventResponse{}, nil
}
func (s *MockServiceServer) DisableEvent(ctx context.Context, req *pb.DisableEventRequest) (*pb.DisableEventResponse, error) {
	return &pb.DisableEventResponse{}, nil
}
