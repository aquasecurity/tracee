package server

import (
	"fmt"
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
			serverFlags: []string{"http.address=127.0.0.1:8080"},
			expectedServer: &Server{
				HTTPServer: http.New("127.0.0.1:8080"),
			},
			expectedError: nil,
		},
		{
			testName:    "http server only just port",
			serverFlags: []string{"http.address=:8080"},
			expectedServer: &Server{
				HTTPServer: http.New(":8080"),
			},
			expectedError: nil,
		},
		{
			testName:    "grpc server only",
			serverFlags: []string{"grpc.address=unix:/tmp/tracee.sock"},
			expectedServer: &Server{
				GRPCServer: grpc.New("unix", "/tmp/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "http and grpc server",
			serverFlags: []string{
				"http.address=127.0.0.1:8080",
				"grpc.address=unix:/tmp/tracee.sock",
			},
			expectedServer: &Server{
				HTTPServer: http.New("127.0.0.1:8080"),
				GRPCServer: grpc.New("unix", "/tmp/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with unix socket",
			serverFlags: []string{
				"grpc.address=unix",
			},
			expectedServer: &Server{
				GRPCServer: grpc.New("unix", "/var/run/tracee.sock"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with tcp address",
			serverFlags: []string{
				"grpc.address=tcp:4466",
			},
			expectedServer: &Server{
				GRPCServer: grpc.New("tcp", "4466"),
			},
			expectedError: nil,
		},
		{
			testName: "grpc server with tcp  only",
			serverFlags: []string{
				"grpc.address=tcp",
			},
			expectedServer: &Server{
				GRPCServer: grpc.New("tcp", "4466"),
			},
			expectedError: nil,
		},
		{
			testName:       "invalid server flag",
			serverFlags:    []string{"invalid"},
			expectedServer: nil,
			expectedError:  fmt.Errorf("cannot process the flag: try grpc.Xxx or http.Xxx instead"),
		},
		{
			testName:       "invalid server flag",
			serverFlags:    []string{"invalid.invalid"},
			expectedServer: nil,
			expectedError:  fmt.Errorf("cannot process the flag: try grpc.Xxx or http.Xxx instead"),
		},
		{
			testName:       "invalid http flag",
			serverFlags:    []string{"http.invalid=true"},
			expectedServer: nil,
			expectedError:  fmt.Errorf("invalid http flag, consider using one of the following commands: address, metrics, healthz, pprof, pyroscope"),
		},
		{
			testName:       "invalid grpc flag",
			serverFlags:    []string{"grpc.invalid=true"},
			expectedServer: nil,
			expectedError:  fmt.Errorf("invalid grpc flag, consider using address"),
		},
		{
			testName:       "invalid grpc protocol",
			serverFlags:    []string{"grpc.address=invalid:4466"},
			expectedServer: nil,
			expectedError:  fmt.Errorf("grpc supported protocols are tcp or unix. eg: tcp:4466, unix:/var/run/tracee.sock"),
		},
		{
			testName:       "invalid http protocol",
			serverFlags:    []string{"http.address=invalid:8080"},
			expectedServer: nil,
			expectedError:  fmt.Errorf("invalid http address"),
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			server, err := PrepareServer(testcase.serverFlags)
			if err != nil {
				require.NotNil(t, testcase.expectedError)
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedServer, server)
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
