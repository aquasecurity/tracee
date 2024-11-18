package client

import (
	"fmt"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// github.com/aquasecurity/tracee/cmd/traceectl holds the gRPC connection and service client.
const (
	// unix socket
	PROTOCOL_UNIX = "unix"
	PROTOCOL_TCP  = "tcp"
	SOCKET        = "/tmp/tracee.sock"
)

type ServerInfo struct {
	ConnectionType string // Field to specify connection type (e.g., "unix" or "tcp")
	ADDR           string // Address for the connection // Path for the Unix socket, if using Unix connection or IP and port for tcp
}

// this function use grpc to connect the server
// it can connect to the server with tcp stream or unix socket
func connectToServer(serverInfo ServerInfo) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	// Use switch case to determine connection type
	var conn *grpc.ClientConn
	var err error
	err = determineConnectionType(serverInfo)
	if err != nil {
		return nil, err
	}
	switch serverInfo.ConnectionType {
	case PROTOCOL_UNIX:
		// Dial a Unix socket
		address := fmt.Sprintf("unix://%s", serverInfo.ADDR)
		conn, err = grpc.NewClient(address, opts...)

		if err != nil {
			log.Fatalf("failed to connect to server: %v", err)
			return nil, err
		}
	case PROTOCOL_TCP:
		// Dial a TCP address
		address := fmt.Sprintf(serverInfo.ADDR)
		conn, err = grpc.NewClient(address, opts...)

		if err != nil {
			log.Fatalf("failed to connect to server: %v", err)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported connection type: %s", serverInfo.ConnectionType)
	}

	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
		return nil, err
	}
	return conn, nil
}

func determineConnectionType(serverInfo ServerInfo) error {
	if strings.Contains(serverInfo.ADDR, ":") && isValidTCPAddress(serverInfo.ADDR) {
		// It's a TCP address
		serverInfo.ConnectionType = PROTOCOL_TCP
		return nil
	}
	if strings.HasPrefix(serverInfo.ADDR, "/") {
		// It's a Unix socket path
		serverInfo.ConnectionType = PROTOCOL_UNIX
		return nil
	}

	return fmt.Errorf("unsupported connection type: %s", serverInfo.ADDR)

}

// isValidTCPAddress checks if the address is a valid IP:PORT format
func isValidTCPAddress(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return false
	}

	// Validate port number
	if _, err := net.LookupPort("tcp", port); err != nil {
		return false
	}

	return true
}
