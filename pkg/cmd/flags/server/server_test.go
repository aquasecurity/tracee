package server

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
)

func TestPrepareServer(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		testName       string
		serverFlags    []string
		expectedServer *Server
		expectedError  error
	}{
		{
			testName:    "http server only",
			serverFlags: []string{HTTPAddressFlag + "=127.0.0.1:8080"},
			expectedServer: &Server{
				HTTP: http.New("127.0.0.1:8080"),
			},
			expectedError: nil,
		},
		{
			testName:    "http server only just port",
			serverFlags: []string{HTTPAddressFlag + "=:8080"},
			expectedServer: &Server{
				HTTP: http.New(":8080"),
			},
			expectedError: nil,
		},
		{
			testName:    "grpc server only",
			serverFlags: []string{GRPCAddressFlag + "=unix:/tmp/tracee.sock"},
			expectedServer: &Server{
				GRPC: grpc.New("unix", "/tmp/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "http and grpc server",
			serverFlags: []string{
				HTTPAddressFlag + "=127.0.0.1:8080",
				GRPCAddressFlag + "=unix:/tmp/tracee.sock",
			},
			expectedServer: &Server{
				HTTP: http.New("127.0.0.1:8080"),
				GRPC: grpc.New("unix", "/tmp/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with unix socket",
			serverFlags: []string{
				GRPCAddressFlag + "=unix",
			},
			expectedServer: &Server{
				GRPC: grpc.New("unix", "/var/run/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with tcp address",
			serverFlags: []string{
				GRPCAddressFlag + "=tcp:4466",
			},
			expectedServer: &Server{
				GRPC: grpc.New("tcp", "4466"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with tcp  only",
			serverFlags: []string{
				GRPCAddressFlag + "=tcp",
			},
			expectedServer: &Server{
				GRPC: grpc.New("tcp", "4466"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with default flag",
			serverFlags: []string{
				GRPCEndpointFlag,
			},
			expectedServer: &Server{
				GRPC: grpc.New("unix", "/var/run/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc and http servers together",
			serverFlags: []string{
				HTTPAddressFlag + "=:8080",
				GRPCEndpointFlag,
				MetricsEndpointFlag,
			},
			expectedServer: &Server{
				HTTP: GetHttpTestServer(":8080", true, false, false, false),
				GRPC: grpc.New("unix", "/var/run/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "explicit grpc-address overrides grpc flag",
			serverFlags: []string{
				GRPCEndpointFlag,
				GRPCAddressFlag + "=tcp:8080",
			},
			expectedServer: &Server{
				GRPC: grpc.New("tcp", "8080"),
			},
			expectedError: nil,
		},
		{
			testName: "http server with metrics",
			serverFlags: []string{
				HTTPAddressFlag + "=:3366",
				MetricsEndpointFlag,
			},
			expectedServer: &Server{
				HTTP: GetHttpTestServer(":3366", true, false, false, false),
			},
			expectedError: nil,
		},
		{
			testName: "http server with multiple features",
			serverFlags: []string{
				HTTPAddressFlag + "=:3366",
				MetricsEndpointFlag,
				HealthzEndpointFlag,
				PProfEndpointFlag,
				PyroscopeAgentEndpointFlag,
			},
			expectedServer: &Server{
				HTTP: GetHttpTestServer(":3366", true, true, true, true),
			},
			expectedError: nil,
		},
		{
			testName: "http features without address creates default server",
			serverFlags: []string{
				MetricsEndpointFlag,
				PProfEndpointFlag,
			},
			expectedServer: &Server{
				HTTP: GetHttpTestServer("localhost:3366", true, true, false, false),
			},
			expectedError: nil,
		},
		{
			testName:       "invalid server flag",
			serverFlags:    []string{"invalid"},
			expectedServer: nil,
			expectedError:  errors.New("invalid server flag 'invalid': supported flags are metrics, healthz, pprof, pyroscope"),
		},
		{
			testName:       "invalid server flag with value",
			serverFlags:    []string{"invalid=value"},
			expectedServer: nil,
			expectedError:  errors.New("invalid server flag with value 'invalid': supported flags are http-address, grpc-address"),
		},
		{
			testName:       "invalid grpc protocol",
			serverFlags:    []string{GRPCAddressFlag + "=invalid:4466"},
			expectedServer: nil,
			expectedError:  errors.New("grpc protocol 'invalid' not supported: use tcp:<port> or unix:<socket_path>"),
		},
		{
			testName:       "invalid http address format",
			serverFlags:    []string{HTTPAddressFlag + "=invalid_no_port"},
			expectedServer: nil,
			expectedError:  errors.New("invalid http address 'invalid_no_port': expected format <host:port>"),
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			server, err := PrepareServer(testcase.serverFlags)
			if err != nil {
				require.NotNil(t, testcase.expectedError)
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				require.NotNil(t, server)

				// Compare HTTP server presence and properties
				if testcase.expectedServer.HTTP != nil {
					require.NotNil(t, server.HTTP, "Expected HTTP server to be present")
					assert.Equal(t, testcase.expectedServer.HTTP.MetricsEndpointEnabled(), server.HTTP.MetricsEndpointEnabled(), "Metrics endpoint enablement should match")
				} else {
					assert.Nil(t, server.HTTP, "Expected no HTTP server")
				}

				// Compare GRPC server presence
				if testcase.expectedServer.GRPC != nil {
					assert.NotNil(t, server.GRPC, "Expected GRPC server to be present")
				} else {
					assert.Nil(t, server.GRPC, "Expected no GRPC server")
				}
			}
		})
	}
}

func GetHttpTestServer(listenAddr string, metrics bool, pprof bool, healthz bool, pyroscope bool) *http.Server {
	server := http.New(listenAddr)
	if metrics {
		server.EnableMetricsEndpoint()
	}
	if healthz {
		server.EnableHealthzEndpoint()
	}
	if pprof {
		server.EnablePProfEndpoint()
	}
	if pyroscope {
		err := server.EnablePyroAgent()
		if err != nil {
			panic(err)
		}
	}
	return server
}
