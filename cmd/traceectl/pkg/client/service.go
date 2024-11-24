package client

import (
	"context"
	"log"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"google.golang.org/grpc"
)

type ServiceClient struct {
	conn   *grpc.ClientConn
	client pb.TraceeServiceClient
}

func (tc *ServiceClient) NewServiceClient(serverInfo ServerInfo) error {
	conn, err := connectToServer(serverInfo)
	if err != nil {
		return err
	}
	tc.conn = conn
	tc.client = pb.NewTraceeServiceClient(conn)

	return nil
}
func (tc *ServiceClient) CloseConnection() {
	if err := tc.conn.Close(); err != nil {
		log.Printf("Failed to close connection: %v", err)
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
