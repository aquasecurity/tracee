package client

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

type ServiceClient struct {
	conn   *grpc.ClientConn
	client pb.TraceeServiceClient
}

func NewServiceClient(serverInfo ServerInfo) (*ServiceClient, error) {
	conn, err := connectToServer(serverInfo)
	if err != nil {
		return nil, err
	}
	return &ServiceClient{
		conn:   conn,
		client: pb.NewTraceeServiceClient(conn),
	}, nil
}
func (tc *ServiceClient) CloseConnection() {
	if err := tc.conn.Close(); err != nil {
		return
	}
}
func (tc *ServiceClient) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return tc.client.GetVersion(ctx, req)
}

func (tc *ServiceClient) EnableEvent(ctx context.Context, req *pb.EnableEventRequest) (*pb.EnableEventResponse, error) {
	return tc.client.EnableEvent(ctx, req)
}

func (tc *ServiceClient) DisableEvent(ctx context.Context, req *pb.DisableEventRequest) (*pb.DisableEventResponse, error) {
	return tc.client.DisableEvent(ctx, req)
}

func (tc *ServiceClient) StreamEvents(ctx context.Context, req *pb.StreamEventsRequest) (pb.TraceeService_StreamEventsClient, error) {
	return tc.client.StreamEvents(ctx, req)
}
func (tc *ServiceClient) GetEventDefinitions(ctx context.Context, req *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	return tc.client.GetEventDefinitions(ctx, req)
}
