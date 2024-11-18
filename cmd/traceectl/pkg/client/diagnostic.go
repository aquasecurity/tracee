package client

import (
	"context"
	"log"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"google.golang.org/grpc"
)

// github.com/aquasecurity/tracee/cmd/traceectl holds the gRPC connection and diagnostic client.
type DiagnosticClient struct {
	conn   *grpc.ClientConn
	client pb.DiagnosticServiceClient
}

// Newgithub.com/aquasecurity/tracee/cmd/traceectl initializes a new gRPC client connection.
func (tc *DiagnosticClient) NewDiagnosticClient(serverInfo ServerInfo) error {
	// Connect to the server and handle errors properly
	conn, err := connectToServer(serverInfo)
	if err != nil {
		return err
	}

	// Store the connection and create the service client
	tc.conn = conn
	tc.client = pb.NewDiagnosticServiceClient(conn)

	return nil
}

// Close the gRPC connection.
func (tc *DiagnosticClient) CloseConnection() {
	if err := tc.conn.Close(); err != nil {
		log.Printf("Failed to close connection: %v", err)
		return
	}
}

/*
if you want to add new options to the client, under this section is where you should add them
*/

// sends a GetMetrics request to the server.
func (tc *DiagnosticClient) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	return tc.client.GetMetrics(ctx, req)
}
