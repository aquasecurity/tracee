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
	ExpectedVersion string            = "v0.22.0-15-gd09d7fca0d" // Match the output format
	serverInfo      client.ServerInfo = client.ServerInfo{
		ADDR: client.SOCKET,
	}
)

// MockServiceServer implements the gRPC server interface for testing
type MockServiceServer struct {
	pb.UnimplementedTraceeServiceServer // Embed the unimplemented server
}

// MockDiagnosticServer implements the gRPC server interface for testing
type MockDiagnosticServer struct {
	pb.UnimplementedDiagnosticServiceServer // Embed the unimplemented server
}

// CreateMockServer initializes the gRPC server and binds it to a Unix socket listener
func CreateMockServer() (*grpc.Server, net.Listener, error) {
	// Check for existing Unix socket and remove it if necessary
	if _, err := os.Stat(serverInfo.ADDR); err == nil {
		if err := os.Remove(serverInfo.ADDR); err != nil {
			return nil, nil, fmt.Errorf("failed to cleanup gRPC listening address (%s): %v", serverInfo.ADDR, err)
		}
	}

	// Create the Unix socket listener
	listener, err := net.Listen("unix", serverInfo.ADDR)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Unix socket listener: %v", err)
	}

	// Create a new gRPC server
	server := grpc.NewServer()

	// Register both TraceeService and DiagnosticService with the server
	pb.RegisterTraceeServiceServer(server, &MockServiceServer{})
	pb.RegisterDiagnosticServiceServer(server, &MockDiagnosticServer{})

	return server, listener, nil
}

// StartMockServer starts the gRPC server with both services registered
func StartMockServer() (*grpc.Server, error) {
	mockServer, listener, err := CreateMockServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create mock server: %v", err)
	}

	// Start serving in a goroutine
	go func() {
		if err := mockServer.Serve(listener); err != nil {
			fmt.Printf("gRPC server failed: %v\n", err)
		}
	}()

	return mockServer, nil
}

// StopMockServer stops the server and removes the Unix socket
func StopMockServer(server *grpc.Server) {
	server.GracefulStop()
	if err := os.Remove(serverInfo.ADDR); err != nil {
		fmt.Printf("failed to remove Unix socket: %v\n", err)
	}
}
