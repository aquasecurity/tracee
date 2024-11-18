package client

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

type DiagnosticClient struct {
	conn   *grpc.ClientConn
	client pb.DiagnosticServiceClient
}

func NewDiagnosticClient(serverInfo ServerInfo) (*DiagnosticClient, error) {
	conn, err := connectToServer(serverInfo)
	if err != nil {
		return nil, err
	}
	return &DiagnosticClient{
		conn:   conn,
		client: pb.NewDiagnosticServiceClient(conn),
	}, nil
}
func (tc *DiagnosticClient) CloseConnection() {
	if err := tc.conn.Close(); err != nil {
		return
	}
}
func (tc *DiagnosticClient) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	return tc.client.GetMetrics(ctx, req)
}
