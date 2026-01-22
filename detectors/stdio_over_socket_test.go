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

func TestStdioOverSocket(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		eventID        v1beta1.EventId
		eventName      string
		sockfd         int32
		ip             string
		port           uint32
		saFamily       v1beta1.SaFamilyT
		expectedOutput bool
	}{
		{
			name:           "stdin redirected to socket",
			eventID:        v1beta1.EventId_security_socket_connect,
			eventName:      "security_socket_connect",
			sockfd:         0,
			ip:             "192.168.1.100",
			port:           4444,
			saFamily:       v1beta1.SaFamilyT_AF_INET,
			expectedOutput: true,
		},
		{
			name:           "stdout redirected to socket",
			eventID:        v1beta1.EventId_security_socket_connect,
			eventName:      "security_socket_connect",
			sockfd:         1,
			ip:             "10.0.0.1",
			port:           5555,
			saFamily:       v1beta1.SaFamilyT_AF_INET,
			expectedOutput: true,
		},
		{
			name:           "stderr redirected to socket",
			eventID:        v1beta1.EventId_socket_dup,
			eventName:      "socket_dup",
			sockfd:         2,
			ip:             "172.16.0.1",
			port:           8080,
			saFamily:       v1beta1.SaFamilyT_AF_INET,
			expectedOutput: true,
		},
		{
			name:           "regular socket (fd=3) - should not trigger",
			eventID:        v1beta1.EventId_security_socket_connect,
			eventName:      "security_socket_connect",
			sockfd:         3,
			ip:             "192.168.1.100",
			port:           4444,
			saFamily:       v1beta1.SaFamilyT_AF_INET,
			expectedOutput: false,
		},
		{
			name:           "port 0 - should not trigger",
			eventID:        v1beta1.EventId_security_socket_connect,
			eventName:      "security_socket_connect",
			sockfd:         1,
			ip:             "192.168.1.100",
			port:           0,
			saFamily:       v1beta1.SaFamilyT_AF_INET,
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &StdioOverSocket{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			dataFieldName := "sockfd"
			if tc.eventName == "socket_dup" {
				dataFieldName = "newfd"
			}

			event := &v1beta1.Event{
				Id:   tc.eventID,
				Name: tc.eventName,
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/bin/bash"},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewInt32Value(dataFieldName, tc.sockfd),
					{
						Name: "remote_addr",
						Value: &v1beta1.EventValue_Sockaddr{
							Sockaddr: &v1beta1.SockAddr{
								SaFamily: tc.saFamily,
								SinAddr:  tc.ip,
								SinPort:  tc.port,
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
