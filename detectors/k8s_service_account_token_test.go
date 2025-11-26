package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func TestK8SServiceAccountToken(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		execPath       string
		pathname       string
		flags          int32
		expectedOutput bool
	}{
		{
			name:           "read service account token by malicious process",
			execPath:       "/usr/bin/malicious",
			pathname:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
			flags:          0, // O_RDONLY
			expectedOutput: true,
		},
		{
			name:           "read service account token by kubectl - should not trigger",
			execPath:       "/usr/bin/kubectl",
			pathname:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		{
			name:           "read service account token by kube-proxy - should not trigger",
			execPath:       "/usr/local/bin/kube-proxy",
			pathname:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		{
			name:           "write to token file - should not trigger (not a read)",
			execPath:       "/usr/bin/malicious",
			pathname:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
			flags:          1, // O_WRONLY
			expectedOutput: false,
		},
		{
			name:           "read different file - should not trigger",
			execPath:       "/usr/bin/malicious",
			pathname:       "/etc/passwd",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &K8SServiceAccountToken{}
			err := detector.Init(detection.DetectorParams{Logger: &mockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_file_open,
				Name: "security_file_open",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: tc.execPath},
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
