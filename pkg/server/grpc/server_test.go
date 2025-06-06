package grpc

import (
	"context"
	"log"
	"os"
	"testing"

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
