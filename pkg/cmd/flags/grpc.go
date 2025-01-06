package flags

import (
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
)

func PrepareGRPCServer(listenAddr string) (*grpc.Server, error) {
	if len(listenAddr) == 0 {
		return nil, nil
	}

	addr := strings.SplitN(listenAddr, ":", 2)

	if addr[0] != "tcp" && addr[0] != "unix" {
		return nil, errfmt.Errorf("grpc supported protocols are tcp or unix. eg: tcp:4466, unix:/tmp/tracee.sock")
	}

	if len(addr[1]) == 0 {
		return nil, errfmt.Errorf("grpc address cannot be empty")
	}

	// cleanup listen address if needed (unix socket), for example if a panic happened
	if addr[0] == "unix" {
		if _, err := os.Stat(addr[1]); err == nil {
			err := os.Remove(addr[1])
			if err != nil {
				return nil, errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", addr[1], err)
			}
		}
	}

	return grpc.New(addr[0], addr[1]), nil
}
