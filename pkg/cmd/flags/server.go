package flags

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
)

const (
	ServerFlag = "server"

	httpAddressFlag    = "http-address"
	grpcAddressFlag    = "grpc-address"
	defaultHTTPAddress = ":3366"
	defaultGRPCPort    = "4466"
	defaultGRPCPath    = "/var/run/tracee.sock"

	// http endpoints
	metricsFlag   = "metrics"
	healthzFlag   = "healthz"
	pprofFlag     = "pprof"
	pyroscopeFlag = "pyroscope"

	invalidServerFlagError      = "invalid server flag: '%s', use 'trace man server' for more info"
	invalidGRPCProtocolError    = "invalid grpc protocol: '%s', use 'trace man server' for more info"
	invalidHTTPAddressError     = "invalid http address: '%s', use 'trace man server' for more info"
	invalidHTTPHostError        = "invalid http host: '%s', use 'trace man server' for more info"
	invalidPortNumberError      = "invalid port number '%s', use 'trace man server' for more info"
	invalidPortNumberRangeError = "invalid port number '%s', value must be between 0 and 65535, use 'trace man server' for more info"
)

// ServerConfig represents the server configuration
type ServerConfig struct {
	HttpAddress string `mapstructure:"http-address"`
	GrpcAddress string `mapstructure:"grpc-address"`
	Metrics     bool   `mapstructure:"metrics"`
	Pprof       bool   `mapstructure:"pprof"`
	Healthz     bool   `mapstructure:"healthz"`
	Pyroscope   bool   `mapstructure:"pyroscope"`

	http *http.Server
	grpc *grpc.Server
}

// GetHTTPServer returns the HTTP server
func (s *ServerConfig) GetHTTPServer() *http.Server {
	return s.http
}

// GetGRPCServer returns the gRPC server
func (s *ServerConfig) GetGRPCServer() *grpc.Server {
	return s.grpc
}

// flags returns the server flags
func (s *ServerConfig) flags() []string {
	flags := make([]string, 0)

	if s.GrpcAddress != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", grpcAddressFlag, s.GrpcAddress))
	}
	if s.HttpAddress != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", httpAddressFlag, s.HttpAddress))
	}
	if s.Metrics {
		flags = append(flags, metricsFlag)
	}
	if s.Pprof {
		flags = append(flags, pprofFlag)
	}
	if s.Healthz {
		flags = append(flags, healthzFlag)
	}
	if s.Pyroscope {
		flags = append(flags, pyroscopeFlag)
	}
	return flags
}

// PrepareServer prepares the server based on the server flags
func PrepareServer(serverSlice []string) (ServerConfig, error) {
	var server ServerConfig

	for _, flag := range serverSlice {
		values := strings.SplitN(flag, "=", 2)

		flagName := values[0]

		if len(values) != 2 && !isServerBoolFlag(flagName) {
			return server, errfmt.Errorf(invalidServerFlagError, flagName)
		}

		if len(values) != 1 && isServerBoolFlag(flagName) {
			return server, errfmt.Errorf(invalidServerFlagError, flagName)
		}

		switch flagName {
		case httpAddressFlag: // http-address=<host:port>
			flagValue := values[1]
			if err := validateHTTPAddr(flagValue); err != nil {
				return server, err
			}
			server.http = http.New(flagValue)
		case grpcAddressFlag: // grpc-address=protocol:address
			flagValue := values[1]
			protocol, address, err := parseAndValidateGRPCAddr(flagValue)
			if err != nil {
				return server, err
			}
			server.grpc = grpc.New(protocol, address)
		case metricsFlag:
			server.Metrics = true
		case healthzFlag:
			server.Healthz = true
		case pprofFlag:
			server.Pprof = true
		case pyroscopeFlag:
			server.Pyroscope = true
		default:
			return server, errfmt.Errorf(invalidServerFlagError, flagName)
		}
	}

	if err := server.enableHttpEndpoints(); err != nil {
		return server, err
	}

	// Enable gRPC health service if healthz flag is set
	if server.Healthz && server.grpc != nil {
		server.grpc.EnableHealthService()
	}

	return server, nil
}

// hasAnyHttpEndpointEnabled checks if any HTTP endpoint is enabled
func (s *ServerConfig) hasAnyHttpEndpointEnabled() bool {
	return s.Metrics || s.Healthz || s.Pprof || s.Pyroscope
}

// enableHttpEndpoints enables the configured HTTP endpoints on the server
func (s *ServerConfig) enableHttpEndpoints() error {
	if !s.hasAnyHttpEndpointEnabled() {
		return nil
	}

	// if a flag is set, but the server is not configured, set a default HTTP server
	if s.http == nil {
		s.http = http.New(defaultHTTPAddress)
	}

	if s.Metrics {
		s.http.EnableMetricsEndpoint()
	}
	if s.Healthz {
		s.http.SetHealthzEnabled()
	}
	if s.Pprof {
		s.http.EnablePProfEndpoint()
	}
	if s.Pyroscope {
		if err := s.http.EnablePyroAgent(); err != nil {
			return err
		}
	}

	return nil
}

// validateHTTPAddr validates an HTTP address
func validateHTTPAddr(addr string) error {
	// Split the address into host and port.
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return errfmt.Errorf(invalidHTTPAddressError, addr)
	}

	// If a host is specified, do basic validation
	if host != "" {
		// Accept IP addresses and basic hostname formats
		// For CLI tools, we can be permissive and let network operations
		// handle detailed validation when the server actually starts
		if net.ParseIP(host) == nil {
			// Basic hostname validation: no spaces, reasonable length
			if len(host) > 253 || strings.Contains(host, " ") {
				return errfmt.Errorf(invalidHTTPHostError, host)
			}
		}
	}

	return validatePort(portStr)
}

// parseAndValidateGRPCAddr parses and validates a gRPC address
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

	return "", "", errfmt.Errorf(invalidGRPCProtocolError, protocol)
}

// validatePort validates a port number
func validatePort(port string) error {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return errfmt.Errorf(invalidPortNumberError, port)
	}
	if portInt < 0 || portInt > 65535 {
		return errfmt.Errorf(invalidPortNumberRangeError, port)
	}
	return nil
}

// isServerBoolFlag checks if a flag is a server boolean flag
func isServerBoolFlag(flagName string) bool {
	return flagName == metricsFlag ||
		flagName == healthzFlag ||
		flagName == pprofFlag ||
		flagName == pyroscopeFlag
}

// invalidServerFlagErrorMsg formats the error message for an invalid server flag.
func invalidServerFlagErrorMsg(flag string) string {
	return fmt.Sprintf(invalidServerFlagError, flag)
}

// invalidGRPCProtocolErrorMsg formats the error message for an invalid gRPC protocol.
func invalidGRPCProtocolErrorMsg(protocol string) string {
	return fmt.Sprintf(invalidGRPCProtocolError, protocol)
}

// invalidHTTPAddressErrorMsg formats the error message for an invalid HTTP address.
func invalidHTTPAddressErrorMsg(addr string) string {
	return fmt.Sprintf(invalidHTTPAddressError, addr)
}

// invalidHTTPHostErrorMsg formats the error message for an invalid HTTP host.
func invalidHTTPHostErrorMsg(host string) string {
	return fmt.Sprintf(invalidHTTPHostError, host)
}

// invalidPortNumberErrorMsg formats the error message for an invalid port number.
func invalidPortNumberErrorMsg(port string) string {
	return fmt.Sprintf(invalidPortNumberError, port)
}

// invalidPortNumberRangeErrorMsg formats the error message for an invalid port number out of range.
func invalidPortNumberRangeErrorMsg(port string) string {
	return fmt.Sprintf(invalidPortNumberRangeError, port)
}
