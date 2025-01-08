package flags

import (
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
)

func PrepareServer(cmd *cobra.Command, server client.ServerInfo) (client.ServerInfo, error) {
	var err error
	var address string
	err = determineConnectionType(server)
	if err != nil {
		return server, err
	}
	switch server.ConnectionType {
	case client.Protocol_UNIX:
		address = fmt.Sprintf("unix://%s", server.Addr)
	case client.Protocol_TCP:
		address = fmt.Sprintf(server.Addr)
	default:
		return server, fmt.Errorf("unsupported connection type: %s", server.ConnectionType)
	}
	server.Addr = address
	return server, nil
}

func determineConnectionType(server client.ServerInfo) error {
	if strings.Contains(server.Addr, ":") && isValidTCPAddress(server.Addr) {
		server.ConnectionType = client.Protocol_TCP
		return nil
	}
	if strings.HasPrefix(server.Addr, "/") {
		server.ConnectionType = client.Protocol_UNIX
		return nil
	}

	return fmt.Errorf("unsupported connection type: %s", server.Addr)
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
