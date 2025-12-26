package grpc

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func TestServer(t *testing.T) {
	t.Parallel()

	tempDir, err := os.MkdirTemp("", "tracee-tests")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	unixSock := tempDir + "/tracee.sock"
	defer os.Remove(unixSock) // clean up

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer := New("unix", unixSock)

	go grpcServer.Start(ctx, nil, nil)

	// Wait for the server to start and create the socket
	maxRetries := 50
	for i := 0; i < maxRetries; i++ {
		if _, err := os.Stat(unixSock); err == nil {
			break // Socket exists, server is ready
		}
		if i == maxRetries-1 {
			t.Fatal("Server did not start within expected time")
		}
		time.Sleep(10 * time.Millisecond) // Short wait between checks
	}

	c := grpcClient("unix", unixSock)

	_, err = c.GetVersion(ctx, &pb.GetVersionRequest{})
	assert.NoError(t, err)
}

func grpcClient(protocol, addr string) pb.TraceeServiceClient {
	sock := protocol + ":" + addr
	conn, err := grpc.NewClient(sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return pb.NewTraceeServiceClient(conn)
}

func TestServer_Address(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol string
		addr     string
		expected string
	}{
		{
			name:     "tcp with port",
			protocol: "tcp",
			addr:     "4466",
			expected: "tcp:4466",
		},
		{
			name:     "unix socket",
			protocol: "unix",
			addr:     "/var/run/tracee.sock",
			expected: "unix:/var/run/tracee.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.protocol, tt.addr)
			assert.Equal(t, tt.expected, s.Address())
		})
	}
}
