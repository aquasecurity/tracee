package server

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
)

// TODO: this should be extracted to be under 'pkg/cmd/flags' now that tracee-rules no longer uses server functionality.

type Server struct {
	HTTP *http.Server
	GRPC *grpc.Server
}

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
		// Skip empty strings (default values)
		if strings.TrimSpace(endpoint) == "" {
			continue
		}

		// Parse the new flag format: http-address=value, grpc-address=value, metrics, etc.
		if strings.Contains(endpoint, "=") {
			// Address flags with values
			parts := strings.SplitN(endpoint, "=", 2)
			flagName := parts[0]
			flagValue := parts[1]

			switch flagName {
			case HTTPAddressFlag:
				if !isValidAddr(flagValue) {
					return nil, errfmt.Errorf("invalid http address '%s': expected format <host:port>", flagValue)
				}
				server.HTTP = http.New(flagValue)
			case GRPCAddressFlag:
				addressParts := strings.SplitN(flagValue, ":", 2)
				switch addressParts[0] {
				case "unix":
					if len(addressParts) == 1 {
						addressParts = append(addressParts, "/var/run/tracee.sock")
					}
					if _, err = os.Stat(addressParts[1]); err == nil {
						err = os.Remove(addressParts[1])
						if err != nil {
							return nil, errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", addressParts[1], err)
						}
					}
				case "tcp":
					if len(addressParts) == 1 {
						addressParts = append(addressParts, "4466")
					}
				default:
					return nil, errfmt.Errorf("grpc protocol '%s' not supported: use tcp:<port> or unix:<socket_path>", addressParts[0])
				}
				server.GRPC = grpc.New(addressParts[0], addressParts[1])
			default:
				return nil, errfmt.Errorf("invalid server flag with value '%s': supported flags are %s, %s", flagName, HTTPAddressFlag, GRPCAddressFlag)
			}
		} else {
			// Boolean flags without values
			switch endpoint {
			case MetricsEndpointFlag:
				enableMetrics = true
			case HealthzEndpointFlag:
				enableHealthz = true
			case PProfEndpointFlag:
				enablePProf = true
			case PyroscopeAgentEndpointFlag:
				enablePyroscope = true
			case GRPCEndpointFlag:
				// Create default GRPC server if none exists
				if server.GRPC == nil {
					server.GRPC = grpc.New("unix", "/var/run/tracee.sock")
				}
			default:
				return nil, errfmt.Errorf("invalid server flag '%s': supported flags are %s, %s, %s, %s, %s", endpoint, MetricsEndpointFlag, HealthzEndpointFlag, PProfEndpointFlag, PyroscopeAgentEndpointFlag, GRPCEndpointFlag)
			}
		}
	}

	if enableMetrics || enableHealthz || enablePProf || enablePyroscope {
		if server.HTTP == nil {
			server.HTTP = http.New("localhost:3366")
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

func isValidAddr(addr string) bool {
	// Check if the address contains a port.
	if !strings.Contains(addr, ":") {
		return false
	}

	// Split the address into host and port.
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	// If a host is specified, do basic validation
	if host != "" {
		// Accept IP addresses and basic hostname formats
		// For CLI tools, we can be permissive and let network operations
		// handle detailed validation when the server actually starts
		if net.ParseIP(host) == nil {
			// Basic hostname validation: no spaces, reasonable length
			if len(host) > 253 || strings.Contains(host, " ") {
				return false
			}
		}
	}

	// Check if the port is a valid integer and within the allowed range.
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return false
	}
	if port == 0 {
		return false
	}

	return true
}
