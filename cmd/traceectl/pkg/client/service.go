package client

import (
	"context"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func (tc *Server) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return tc.serviceClient.GetVersion(ctx, req)
}

func (tc *Server) EnableEvent(ctx context.Context, req *pb.EnableEventRequest) (*pb.EnableEventResponse, error) {
	return tc.serviceClient.EnableEvent(ctx, req)
}

func (tc *Server) DisableEvent(ctx context.Context, req *pb.DisableEventRequest) (*pb.DisableEventResponse, error) {
	return tc.serviceClient.DisableEvent(ctx, req)
}

func (tc *Server) StreamEvents(ctx context.Context, req *pb.StreamEventsRequest) (pb.TraceeService_StreamEventsClient, error) {
	return tc.serviceClient.StreamEvents(ctx, req)
}
func (tc *Server) GetEventDefinitions(ctx context.Context, req *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	return tc.serviceClient.GetEventDefinitions(ctx, req)
}
