package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestDockerAbuse_FileOpen(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pathname       string
		flags          int32
		expectedOutput bool
	}{
		{
			name:           "write to /var/run/docker.sock",
			pathname:       "/var/run/docker.sock",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "write to /custom/path/docker.sock",
			pathname:       "/custom/path/docker.sock",
			flags:          1, // O_WRONLY
			expectedOutput: true,
		},
		{
			name:           "read docker.sock - should not trigger",
			pathname:       "/var/run/docker.sock",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		// Note: different file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &DockerAbuse{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_file_open,
				Name: "security_file_open",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/curl"},
					},
					Container: &v1beta1.Container{
						Id:      "test-container",
						Started: true,
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewInt32Value("flags", tc.flags),
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection")
			} else {
				assert.Len(t, output, 0, "Expected no detection")
			}
		})
	}
}

func TestDockerAbuse_SocketConnect(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		saFamily       v1beta1.SaFamilyT
		sunPath        string
		expectedOutput bool
	}{
		{
			name:           "connect to /var/run/docker.sock via Unix socket",
			saFamily:       v1beta1.SaFamilyT_AF_UNIX,
			sunPath:        "/var/run/docker.sock",
			expectedOutput: true,
		},
		{
			name:           "connect to /custom/path/docker.sock via Unix socket",
			saFamily:       v1beta1.SaFamilyT_AF_UNIX,
			sunPath:        "/custom/path/docker.sock",
			expectedOutput: true,
		},
		{
			name:           "connect to different socket - should not trigger",
			saFamily:       v1beta1.SaFamilyT_AF_UNIX,
			sunPath:        "/var/run/other.sock",
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &DockerAbuse{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_socket_connect,
				Name: "security_socket_connect",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/curl"},
					},
					Container: &v1beta1.Container{
						Id:      "test-container",
						Started: true,
					},
				},
				Data: []*v1beta1.EventValue{
					{
						Name: "remote_addr",
						Value: &v1beta1.EventValue_Sockaddr{
							Sockaddr: &v1beta1.SockAddr{
								SaFamily: tc.saFamily,
								SunPath:  tc.sunPath,
							},
						},
					},
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection")
			} else {
				assert.Len(t, output, 0, "Expected no detection")
			}
		})
	}
}

func TestDockerAbuse_SocketConnect_NonUnix(t *testing.T) {
	t.Parallel()

	detector := &DockerAbuse{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	// Test AF_INET socket (should not trigger - not a Unix socket)
	event := &v1beta1.Event{
		Id:   v1beta1.EventId_security_socket_connect,
		Name: "security_socket_connect",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/curl"},
			},
			Container: &v1beta1.Container{
				Id:      "test-container",
				Started: true,
			},
		},
		Data: []*v1beta1.EventValue{
			{
				Name: "remote_addr",
				Value: &v1beta1.EventValue_Sockaddr{
					Sockaddr: &v1beta1.SockAddr{
						SaFamily: v1beta1.SaFamilyT_AF_INET,
						SinAddr:  "10.225.0.2",
						SinPort:  53,
					},
				},
			},
		},
	}

	output, err := detector.OnEvent(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, output, 0, "Expected no detection for AF_INET socket")
}
