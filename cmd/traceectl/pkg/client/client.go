package client

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	Protocol_UNIX = "unix"
	Protocol_TCP  = "tcp"
	Socket        = "/var/run/tracee.sock"
)

type ServerInfo struct {
	ConnectionType string
	Addr           string
}

func connectToServer(server ServerInfo) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	var conn *grpc.ClientConn
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient(server.Addr, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
