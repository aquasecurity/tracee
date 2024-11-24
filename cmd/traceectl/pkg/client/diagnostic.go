package client

import (
	"context"
	"log"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"google.golang.org/grpc"
)

type DiagnosticClient struct {
	conn   *grpc.ClientConn
	client pb.DiagnosticServiceClient
}

func (tc *DiagnosticClient) NewDiagnosticClient(serverInfo ServerInfo) error {
	conn, err := connectToServer(serverInfo)
	if err != nil {
		return err
	}
	tc.conn = conn
	tc.client = pb.NewDiagnosticServiceClient(conn)

	return nil
}
func (tc *DiagnosticClient) CloseConnection() {
	if err := tc.conn.Close(); err != nil {
		log.Printf("Failed to close connection: %v", err)
		return
	}
}
func (tc *DiagnosticClient) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	return tc.client.GetMetrics(ctx, req)
}
