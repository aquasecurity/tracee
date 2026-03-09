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

func TestKubernetesApiConnection(t *testing.T) {
	t.Parallel()

	detector := &KubernetesApiConnection{}
	err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	// Step 1: Process exec with K8s env var to cache the API address
	execEvent := &v1beta1.Event{
		Id:   v1beta1.EventId_sched_process_exec,
		Name: "sched_process_exec",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/kubectl"},
			},
			Container: &v1beta1.Container{
				Id:      "test-container-123",
				Started: true,
			},
		},
		Data: []*v1beta1.EventValue{
			{
				Name: "env",
				Value: &v1beta1.EventValue_StrArray{
					StrArray: &v1beta1.StringArray{
						Value: []string{
							"PATH=/usr/bin",
							"KUBERNETES_SERVICE_HOST=10.96.0.1",
							"KUBERNETES_SERVICE_PORT=443",
						},
					},
				},
			},
		},
	}

	output, err := detector.OnEvent(context.Background(), execEvent)
	require.NoError(t, err)
	assert.Len(t, output, 0, "Exec event should not produce detection")

	// Step 2: Socket connect to the K8s API address
	connectEvent := &v1beta1.Event{
		Id:   v1beta1.EventId_security_socket_connect,
		Name: "security_socket_connect",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/kubectl"},
			},
			Container: &v1beta1.Container{
				Id:      "test-container-123",
				Started: true,
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("sockfd", 3),
			{
				Name: "remote_addr",
				Value: &v1beta1.EventValue_Sockaddr{
					Sockaddr: &v1beta1.SockAddr{
						SaFamily: v1beta1.SaFamilyT_AF_INET,
						SinAddr:  "10.96.0.1",
						SinPort:  443,
					},
				},
			},
		},
	}

	output, err = detector.OnEvent(context.Background(), connectEvent)
	require.NoError(t, err)
	assert.Len(t, output, 1, "Expected detection for K8s API connection")

	// Step 3: Connect to different IP - should not trigger
	differentIPEvent := &v1beta1.Event{
		Id:   v1beta1.EventId_security_socket_connect,
		Name: "security_socket_connect",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/usr/bin/curl"},
			},
			Container: &v1beta1.Container{
				Id:      "test-container-123",
				Started: true,
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("sockfd", 3),
			{
				Name: "remote_addr",
				Value: &v1beta1.EventValue_Sockaddr{
					Sockaddr: &v1beta1.SockAddr{
						SaFamily: v1beta1.SaFamilyT_AF_INET,
						SinAddr:  "8.8.8.8",
						SinPort:  80,
					},
				},
			},
		},
	}

	output, err = detector.OnEvent(context.Background(), differentIPEvent)
	require.NoError(t, err)
	assert.Len(t, output, 0, "Should not detect connection to different IP")
}
