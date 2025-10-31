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
)

type Server struct {
	HTTP *http.Server
	GRPC *grpc.Server
}

// PrepareServer prepares the server based on the server flags
func PrepareServer(serverSlice []string) (*Server, error) {
	var err error
	var server Server
	var (
		enableMetrics   = false
		enableHealthz   = false
		enablePProf     = false
		enablePyroscope = false
	)
	for _, endpoint := range serverSlice {
		values := strings.SplitN(endpoint, "=", 2)
		if len(values) != 2 {
			return nil, errfmt.Errorf("invalid server flag: '%s', use 'trace man server' for more info", endpoint)
		}

		flagName := values[0]
		flagValue := values[1]

		switch flagName {
		case HTTPAddressFlag: // http-address=<host:port>
			err = validateHTTPAddr(flagValue)
			if err != nil {
				return nil, err
			}
			server.HTTP = http.New(flagValue)
		case GRPCAddressFlag: // grpc-address=protocol:address
			protocol, address, err := parseAndValidateGRPCAddr(flagValue)
			if err != nil {
				return nil, err
			}
			server.GRPC = grpc.New(protocol, address)
		case MetricsEndpointFlag: // metrics
			enableMetrics, err = validateAndGetBool(flagName, flagValue)
			if err != nil {
				return nil, err
			}
		case HealthzEndpointFlag: // healthz
			enableHealthz, err = validateAndGetBool(flagName, flagValue)
			if err != nil {
				return nil, err
			}
		case PProfEndpointFlag: // pprof
			enablePProf, err = validateAndGetBool(flagName, flagValue)
			if err != nil {
				return nil, err
			}
		case PyroscopeAgentEndpointFlag: // pyroscope
			enablePyroscope, err = validateAndGetBool(flagName, flagValue)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errfmt.Errorf("invalid server flag: '%s', use 'trace man server' for more info", flagName)
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

func parseAndValidateGRPCAddr(addr string) (string, string, error) {
	// Split the address into protocol and address.
	values := strings.SplitN(addr, ":", 2)
	protocol := values[0]

	switch protocol {
	case "tcp":
		if len(values) == 2 {
			port := values[1]
			err := validatePort(port)
			if err != nil {
				return "", "", err
			}
			return protocol, port, nil
		}
		return protocol, defaultGRPCPort, nil
	case "unix":
		if len(values) == 2 {
			path := values[1]
			if _, err := os.Stat(path); err == nil {
				err = os.Remove(path)
				if err != nil {
					return "", "", errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", path, err)
				}
			}
			return protocol, path, nil
		}
		return protocol, defaultGRPCPath, nil
	}

	return "", "", errfmt.Errorf("invalid grpc protocol: '%s', use 'trace man server' for more info", protocol)
}

func validateAndGetBool(flagName, value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}

	return false, errfmt.Errorf("invalid flag value '%s' for flag '%s', use 'trace man server' for more info", value, flagName)
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
