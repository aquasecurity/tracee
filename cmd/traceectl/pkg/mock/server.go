package mock

import (
	"fmt"
	"net"
	"os"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"

	"google.golang.org/grpc"
)

var (
	ExpectedVersion string            = "v0.22.0-15-gd09d7fca0d"
	serverInfo      client.ServerInfo = client.ServerInfo{
		ADDR: client.SOCKET,
	}
)

type MockServiceServer struct {
	pb.UnimplementedTraceeServiceServer
}
type MockDiagnosticServer struct {
	pb.UnimplementedDiagnosticServiceServer
}

func CreateMockServer() (*grpc.Server, net.Listener, error) {
	if _, err := os.Stat(serverInfo.ADDR); err == nil {
		if err := os.Remove(serverInfo.ADDR); err != nil {
			return nil, nil, fmt.Errorf("failed to cleanup gRPC listening address (%s): %v", serverInfo.ADDR, err)
		}
	}
	listener, err := net.Listen("unix", serverInfo.ADDR)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Unix socket listener: %v", err)
	}
	server := grpc.NewServer()
	pb.RegisterTraceeServiceServer(server, &MockServiceServer{})
	pb.RegisterDiagnosticServiceServer(server, &MockDiagnosticServer{})

	return server, listener, nil
}
func StartMockServer() (*grpc.Server, error) {
	mockServer, listener, err := CreateMockServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create mock server: %v", err)
	}
	go func() {
		if err := mockServer.Serve(listener); err != nil {
			fmt.Printf("gRPC server failed: %v\n", err)
		}
	}()

	return mockServer, nil
}
func StopMockServer(server *grpc.Server) {
	server.GracefulStop()
	if err := os.Remove(serverInfo.ADDR); err != nil {
		fmt.Printf("failed to remove Unix socket: %v\n", err)
	}
}
