package flags

import (
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

	return grpc.New(addr[0], addr[1])
}
