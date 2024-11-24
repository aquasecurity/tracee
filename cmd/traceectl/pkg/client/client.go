package client

import (
	"fmt"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	PROTOCOL_UNIX = "unix"
	PROTOCOL_TCP  = "tcp"
	SOCKET        = "/tmp/tracee.sock"
)

type ServerInfo struct {
	ConnectionType string
	ADDR           string
}

func connectToServer(serverInfo ServerInfo) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	var conn *grpc.ClientConn
	var err error
	err = determineConnectionType(serverInfo)
	if err != nil {
		return nil, err
	}
	switch serverInfo.ConnectionType {
	case PROTOCOL_UNIX:
		address := fmt.Sprintf("unix://%s", serverInfo.ADDR)
		conn, err = grpc.NewClient(address, opts...)

		if err != nil {
			log.Fatalf("failed to connect to server: %v", err)
			return nil, err
		}
	case PROTOCOL_TCP:
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
		serverInfo.ConnectionType = PROTOCOL_TCP
		return nil
	}
	if strings.HasPrefix(serverInfo.ADDR, "/") {
		serverInfo.ConnectionType = PROTOCOL_UNIX
		return nil
	}

	return fmt.Errorf("unsupported connection type: %s", serverInfo.ADDR)

}
func isValidTCPAddress(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return false
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return false
	}

	return true
}
