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
	Protocol_UNIX = "unix"
	Protocol_TCP  = "tcp"
	Socket        = "/tmp/tracee.sock"
)

type ServerInfo struct {
	connectionType string
	addr           string
}

func connectToServer(serverInfo ServerInfo) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	var conn *grpc.ClientConn
	var err error
	var address string
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	err = determineConnectionType(serverInfo)
	if err != nil {
		return nil, err
	}
	switch serverInfo.connectionType {
	case Protocol_UNIX:
		address = fmt.Sprintf("unix://%s", serverInfo.addr)
	case Protocol_TCP:
		address = fmt.Sprintf(serverInfo.addr)
	default:
		return nil, fmt.Errorf("unsupported connection type: %s", serverInfo.connectionType)
	}
	conn, err = grpc.NewClient(address, opts...)
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
		return nil, err
	}
	return conn, nil
}

func determineConnectionType(serverInfo ServerInfo) error {
	if strings.Contains(serverInfo.addr, ":") && isValidTCPAddress(serverInfo.addr) {
		serverInfo.connectionType = Protocol_TCP
		return nil
	}
	if strings.HasPrefix(serverInfo.addr, "/") {
		serverInfo.connectionType = Protocol_UNIX
		return nil
	}

	return fmt.Errorf("unsupported connection type: %s", serverInfo.addr)

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
