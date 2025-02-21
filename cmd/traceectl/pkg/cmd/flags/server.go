package flags

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
)

const ServerFlag = "server"

func PrepareServer(serverSlice string) (*client.Server, error) {
	var server *client.Server
	var err error
	address := strings.TrimSpace(serverSlice)
	if len(address) == 0 {
		return server, fmt.Errorf("server address cannot be empty")
	}
	if _, ok := os.Stat(address); ok != nil {
		return server, fmt.Errorf("failed to get gRPC listening address (%s): %v", address, ok)
	}
	if server, err = client.NewClient(address); err != nil {
		return server, err
	}
	return server, nil
}
