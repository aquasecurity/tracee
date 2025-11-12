package flags

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
)

const (
	ServerFlag                 = "server"
	HTTPAddressFlag            = "http-address"
	GRPCAddressFlag            = "grpc-address"
	GRPCEndpointFlag           = "grpc"
	MetricsEndpointFlag        = "metrics"
	HealthzEndpointFlag        = "healthz"
	PProfEndpointFlag          = "pprof"
	PyroscopeAgentEndpointFlag = "pyroscope"
	DefaultServerFlagValue     = ""

	defaultHTTPAddress = ":3366"
	defaultGRPCPort    = "4466"
	defaultGRPCPath    = "/var/run/tracee.sock"

	invalidServerFlagError = "invalid server flag: '%s', use 'trace man server' for more info"
)

type Server struct {
	HTTP *http.Server
	GRPC *grpc.Server
}

// PrepareServer prepares the server based on the server flags
func PrepareServer(serverSlice []string) (*Server, error) {
	var (
		err             error
		server          Server
		enableMetrics   = false
		enableHealthz   = false
		enablePProf     = false
		enablePyroscope = false
	)

	for _, flag := range serverSlice {
		values := strings.SplitN(flag, "=", 2)

		flagName := values[0]

		if len(values) != 2 && !isBoolFlag(flagName) {
			return nil, errfmt.Errorf(invalidServerFlagError, flagName)
		}

		if len(values) != 1 && isBoolFlag(flagName) {
			return nil, errfmt.Errorf(invalidServerFlagError, flagName)
		}

		switch flagName {
		case HTTPAddressFlag: // http-address=<host:port>
			flagValue := values[1]
			err = validateHTTPAddr(flagValue)
			if err != nil {
				return nil, err
			}
			server.HTTP = http.New(flagValue)
		case GRPCAddressFlag: // grpc-address=protocol:address
			flagValue := values[1]
			protocol, address, err := parseAndValidateGRPCAddr(flagValue)
			if err != nil {
				return nil, err
			}
			server.GRPC = grpc.New(protocol, address)
		case MetricsEndpointFlag:
			enableMetrics = true
		case HealthzEndpointFlag:
			enableHealthz = true
		case PProfEndpointFlag:
			enablePProf = true
		case PyroscopeAgentEndpointFlag:
			enablePyroscope = true
		default:
			return nil, errfmt.Errorf(invalidServerFlagError, flagName)
		}
	}

	if enableMetrics || enableHealthz || enablePProf || enablePyroscope {
		// if a flag is set, but the server is not configured, set a default HTTP server
		if server.HTTP == nil {
			server.HTTP = http.New(defaultHTTPAddress)
		}
		if enableMetrics {
			server.HTTP.EnableMetricsEndpoint()
		}
		if enableHealthz {
			server.HTTP.EnableHealthzEndpoint()
		}
		if enablePProf {
			server.HTTP.EnablePProfEndpoint()
		}
		if enablePyroscope {
			err = server.HTTP.EnablePyroAgent()
			if err != nil {
				return nil, err
			}
		}
	}

	return &server, nil
}

func validateHTTPAddr(addr string) error {
	// Split the address into host and port.
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return errfmt.Errorf("invalid http address: '%s', use 'trace man server' for more info", addr)
	}

	// If a host is specified, do basic validation
	if host != "" {
		// Accept IP addresses and basic hostname formats
		// For CLI tools, we can be permissive and let network operations
		// handle detailed validation when the server actually starts
		if net.ParseIP(host) == nil {
			// Basic hostname validation: no spaces, reasonable length
			if len(host) > 253 || strings.Contains(host, " ") {
				return errfmt.Errorf("invalid http host: '%s', use 'trace man server' for more info", host)
			}
		}
	}

	return validatePort(portStr)
}

func parseAndValidateGRPCAddr(address string) (protocol string, addr string, err error) {
	// Split the address into protocol and address.
	values := strings.SplitN(address, ":", 2)
	protocol = values[0]

	switch protocol {
	case "tcp":
		if len(values) == 2 {
			addr = values[1]
			err = validatePort(addr)
			if err != nil {
				return "", "", err
			}
			return protocol, addr, nil
		}
		return protocol, defaultGRPCPort, nil
	case "unix":
		if len(values) == 2 {
			addr = values[1]
			if _, err = os.Stat(addr); err == nil {
				err = os.Remove(addr)
				if err != nil {
					return "", "", errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", addr, err)
				}
			}
			return protocol, addr, nil
		}
		return protocol, defaultGRPCPath, nil
	}

	return "", "", errfmt.Errorf("invalid grpc protocol: '%s', use 'trace man server' for more info", protocol)
}

func validatePort(port string) error {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return errfmt.Errorf("invalid port number '%s', use 'trace man server' for more info", port)
	}
	if portInt < 0 || portInt > 65535 {
		return errfmt.Errorf("invalid port number '%s', value must be between 0 and 65535, use 'trace man server' for more info", port)
	}
	return nil
}

func isBoolFlag(flagName string) bool {
	switch flagName {
	case MetricsEndpointFlag, HealthzEndpointFlag, PProfEndpointFlag, PyroscopeAgentEndpointFlag:
		return true
	}
	return false
}
