package flags

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedServer struct {
	HTTPAddress string
	GRPCAddress string
	Metrics     bool
	Pprof       bool
	Healthz     bool
	Pyroscope   bool
}

func TestPrepareServer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName      string
		serverFlags   []string
		expected      *expectedServer
		expectedError error
	}{
		// http-address=<host:port>
		{
			testName:    "http server only",
			serverFlags: []string{"http-address=127.0.0.1:8080"},
			expected: &expectedServer{
				HTTPAddress: "127.0.0.1:8080",
			},
		},
		{
			testName:    "http server with just port",
			serverFlags: []string{"http-address=:8080"},
			expected: &expectedServer{
				HTTPAddress: ":8080",
			},
		},
		// grpc-address=protocol:address
		{
			testName:    "grpc server with unix socket path",
			serverFlags: []string{"grpc-address=unix:/tmp/tracee.sock"},
			expected: &expectedServer{
				GRPCAddress: "unix:/tmp/tracee.sock",
			},
		},
		{
			testName: "grpc server with unix socket only",
			serverFlags: []string{
				"grpc-address=unix",
			},
			expected: &expectedServer{
				GRPCAddress: "unix:/var/run/tracee.sock",
			},
		},
		{
			testName: "grpc server with tcp address",
			serverFlags: []string{
				"grpc-address=tcp:4466",
			},
			expected: &expectedServer{
				GRPCAddress: "tcp:4466",
			},
		},
		{
			testName: "grpc server with tcp  only",
			serverFlags: []string{
				"grpc-address=tcp",
			},
			expected: &expectedServer{
				GRPCAddress: "tcp:4466",
			},
		},
		// --server http-address and grpc-address
		{
			testName: "http and grpc server",
			serverFlags: []string{
				"http-address=127.0.0.1:8080",
				"grpc-address=unix:/tmp/tracee.sock",
			},
			expected: &expectedServer{
				HTTPAddress: "127.0.0.1:8080",
				GRPCAddress: "unix:/tmp/tracee.sock",
			},
		},
		{
			testName: "grpc and http servers with http port only",
			serverFlags: []string{
				"http-address=:8080",
				"grpc-address=unix:/var/run/tracee.sock",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				GRPCAddress: "unix:/var/run/tracee.sock",
			},
		},
		{
			testName: "grpc default unix socket and http servers with http port only",
			serverFlags: []string{
				"http-address=:8080",
				"grpc-address=unix",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				GRPCAddress: "unix:/var/run/tracee.sock",
			},
		},
		{
			testName: "grpc default tcp and http servers with http port only",
			serverFlags: []string{
				"http-address=:8080",
				"grpc-address=tcp",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				GRPCAddress: "tcp:4466",
			},
		},
		{
			testName: "explicit grpc-address flag override",
			serverFlags: []string{
				"grpc-address=unix:/var/run/tracee.sock",
				"grpc-address=tcp:8080",
			},
			expected: &expectedServer{
				GRPCAddress: "tcp:8080",
			},
		},
		// --server metrics
		{
			testName: "http server with metrics",
			serverFlags: []string{
				"metrics",
			},
			expected: &expectedServer{
				HTTPAddress: ":3366",
				Metrics:     true,
			},
		},
		{
			testName: "http server with metrics and http port only",
			serverFlags: []string{
				"http-address=:8080",
				"metrics",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				Metrics:     true,
			},
		},
		// --server pprof
		{
			testName: "http server with pprof",
			serverFlags: []string{
				"pprof",
			},
			expected: &expectedServer{
				HTTPAddress: ":3366",
				Pprof:       true,
			},
		},
		{
			testName: "http server with pprof and http port only",
			serverFlags: []string{
				"http-address=:8080",
				"pprof",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				Pprof:       true,
			},
		},
		// --server healthz
		{
			testName: "http server with healthz",
			serverFlags: []string{
				"healthz",
			},
			expected: &expectedServer{
				HTTPAddress: ":3366",
				Healthz:     true,
			},
		},
		{
			testName: "http server with healthz and http port only",
			serverFlags: []string{
				"http-address=:8080",
				"healthz",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				Healthz:     true,
			},
		},
		// --server pyroscope
		{
			testName: "http server with pyroscope",
			serverFlags: []string{
				"pyroscope",
			},
			expected: &expectedServer{
				HTTPAddress: ":3366",
				Pyroscope:   true,
			},
		},
		{
			testName: "http server with pyroscope and http port only",
			serverFlags: []string{
				"http-address=:8080",
				"pyroscope",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				Pyroscope:   true,
			},
		},
		// --server multiple features
		{
			testName: "http server with multiple features",
			serverFlags: []string{
				"http-address=:3366",
				"metrics",
				"healthz",
				"pprof",
				"pyroscope",
			},
			expected: &expectedServer{
				HTTPAddress: ":3366",
				Metrics:     true,
				Healthz:     true,
				Pprof:       true,
				Pyroscope:   true,
			},
		},
		// all flags together
		{
			testName: "all flags together",
			serverFlags: []string{
				"http-address=:8080",
				"grpc-address=tcp:4466",
				"metrics",
				"healthz",
				"pprof",
				"pyroscope",
			},
			expected: &expectedServer{
				HTTPAddress: ":8080",
				GRPCAddress: "tcp:4466",
				Metrics:     true,
				Healthz:     true,
				Pprof:       true,
				Pyroscope:   true,
			},
		},
		// invalid server flags
		{
			testName:      "invalid server flag",
			serverFlags:   []string{"invalid"},
			expected:      nil,
			expectedError: errors.New(invalidServerFlagErrorMsg("invalid")),
		},
		{
			testName:      "invalid grpc protocol",
			serverFlags:   []string{"grpc-address=invalid:4466"},
			expected:      nil,
			expectedError: errors.New(invalidGRPCProtocolErrorMsg("invalid")),
		},
		{
			testName:      "invalid http address format",
			serverFlags:   []string{"http-address=invalid_no_port"},
			expected:      nil,
			expectedError: errors.New(invalidHTTPAddressErrorMsg("invalid_no_port")),
		},
		{
			testName:      "invalid http port number",
			serverFlags:   []string{"http-address=127.0.0.1:invalid"},
			expected:      nil,
			expectedError: errors.New(invalidPortNumberErrorMsg("invalid")),
		},
		{
			testName:      "invalid http port range",
			serverFlags:   []string{"http-address=127.0.0.1:99999999"},
			expected:      nil,
			expectedError: errors.New(invalidPortNumberRangeErrorMsg("99999999")),
		},
		{
			testName:      "invalid grpc port number",
			serverFlags:   []string{"grpc-address=tcp:invalid"},
			expected:      nil,
			expectedError: errors.New(invalidPortNumberErrorMsg("invalid")),
		},
		{
			testName:      "invalid tcp port range",
			serverFlags:   []string{"grpc-address=tcp:99999999"},
			expected:      nil,
			expectedError: errors.New(invalidPortNumberRangeErrorMsg("99999999")),
		},
		{
			testName:      "invalid metrics flag",
			serverFlags:   []string{"metrics=invalid"},
			expected:      nil,
			expectedError: errors.New(invalidServerFlagErrorMsg("metrics")),
		},
		{
			testName:      "invalid healthz flag",
			serverFlags:   []string{"healthz=invalid"},
			expected:      nil,
			expectedError: errors.New(invalidServerFlagErrorMsg("healthz")),
		},
		{
			testName:      "invalid pprof flag",
			serverFlags:   []string{"pprof=invalid"},
			expected:      nil,
			expectedError: errors.New(invalidServerFlagErrorMsg("pprof")),
		},
		{
			testName:      "invalid pyroscope flag",
			serverFlags:   []string{"pyroscope=invalid"},
			expected:      nil,
			expectedError: errors.New(invalidServerFlagErrorMsg("pyroscope")),
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			server, err := PrepareServer(testcase.serverFlags)
			if err != nil {
				t.Logf("Error for test '%s': %v", testcase.testName, err)
				require.NotNil(t, testcase.expectedError)
				// Error can come from different functions, check that it contains the expected message
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				require.NotNil(t, server)

				if testcase.expected.HTTPAddress != "" {
					require.NotNil(t, server.GetHTTPServer(), "Expected HTTP server to be present")
					assert.Equal(t, testcase.expected.HTTPAddress, server.GetHTTPServer().Address(), "Address should match")
					assert.Equal(t, testcase.expected.Metrics, server.GetHTTPServer().IsMetricsEnabled(), "Metrics endpoint enablement should match")
					assert.Equal(t, testcase.expected.Healthz, server.GetHTTPServer().IsHealthzEnabled(), "Healthz endpoint enablement should match")
					assert.Equal(t, testcase.expected.Pprof, server.GetHTTPServer().IsPProfEnabled(), "Pprof endpoint enablement should match")
					assert.Equal(t, testcase.expected.Pyroscope, server.GetHTTPServer().IsPyroscopeEnabled(), "Pyroscope agent enablement should match")
				} else {
					assert.Nil(t, server.GetHTTPServer(), "Expected no HTTP server")
				}

				if testcase.expected.GRPCAddress != "" {
					assert.NotNil(t, server.GetGRPCServer(), "Expected GRPC server to be present")
					assert.Equal(t, testcase.expected.GRPCAddress, server.GetGRPCServer().Address(), "Address should match")
				} else {
					assert.Nil(t, server.GetGRPCServer(), "Expected no GRPC server")
				}
			}
		})
	}
}

func TestServerConfig_flags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   ServerConfig
		expected []string
	}{
		{
			name:     "empty config",
			config:   ServerConfig{},
			expected: []string{},
		},
		{
			name: "grpc only",
			config: ServerConfig{
				GrpcAddress: "unix:/var/run/tracee.sock",
			},
			expected: []string{
				"grpc-address=unix:/var/run/tracee.sock",
			},
		},
		{
			name: "http only",
			config: ServerConfig{
				HttpAddress: "localhost:8080",
			},
			expected: []string{
				"http-address=localhost:8080",
			},
		},
		{
			name: "http with options",
			config: ServerConfig{
				HttpAddress: "localhost:8080",
				Metrics:     true,
				Pprof:       true,
				Healthz:     true,
				Pyroscope:   true,
			},
			expected: []string{
				"http-address=localhost:8080",
				"metrics",
				"pprof",
				"healthz",
				"pyroscope",
			},
		},
		{
			name: "both http and grpc",
			config: ServerConfig{
				HttpAddress: "localhost:8080",
				GrpcAddress: "unix:/var/run/tracee.sock",
			},
			expected: []string{
				"grpc-address=unix:/var/run/tracee.sock",
				"http-address=localhost:8080",
			},
		},
		{
			name: "both http and grpc with options",
			config: ServerConfig{
				HttpAddress: "localhost:8080",
				GrpcAddress: "unix:/var/run/tracee.sock",
				Metrics:     true,
				Pprof:       true,
				Healthz:     true,
				Pyroscope:   true,
			},
			expected: []string{
				"grpc-address=unix:/var/run/tracee.sock",
				"http-address=localhost:8080",
				"metrics",
				"pprof",
				"healthz",
				"pyroscope",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.flags()
			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestServerConfig_enableHttpEndpoints(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		config          ServerConfig
		expectHTTP      bool
		expectedMetrics bool
		expectedHealthz bool
		expectedPprof   bool
	}{
		{
			name:       "no endpoints enabled",
			config:     ServerConfig{},
			expectHTTP: false,
		},
		{
			name:            "metrics only creates default http server",
			config:          ServerConfig{Metrics: true},
			expectHTTP:      true,
			expectedMetrics: true,
		},
		{
			name:            "healthz only creates default http server",
			config:          ServerConfig{Healthz: true},
			expectHTTP:      true,
			expectedHealthz: true,
		},
		{
			name:          "pprof only creates default http server",
			config:        ServerConfig{Pprof: true},
			expectHTTP:    true,
			expectedPprof: true,
		},
		{
			name: "all endpoints enabled",
			config: ServerConfig{
				Metrics: true,
				Healthz: true,
				Pprof:   true,
			},
			expectHTTP:      true,
			expectedMetrics: true,
			expectedHealthz: true,
			expectedPprof:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.enableHttpEndpoints()
			require.NoError(t, err)

			if tc.expectHTTP {
				require.NotNil(t, tc.config.http)
				assert.Equal(t, tc.expectedMetrics, tc.config.http.IsMetricsEnabled())
				assert.Equal(t, tc.expectedHealthz, tc.config.http.IsHealthzEnabled())
				assert.Equal(t, tc.expectedPprof, tc.config.http.IsPProfEnabled())
			} else {
				assert.Nil(t, tc.config.http)
			}
		})
	}
}
