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

func TestKubernetesCertificateTheft(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		execPath       string
		pathname       string
		flags          int32
		expectedOutput bool
	}{
		{
			name:           "malicious process reading k8s cert",
			execPath:       "/usr/bin/malicious",
			pathname:       "/etc/kubernetes/pki/apiserver.crt",
			flags:          0, // O_RDONLY
			expectedOutput: true,
		},
		{
			name:           "kubelet reading k8s cert - should not trigger",
			execPath:       "/usr/bin/kubelet",
			pathname:       "/etc/kubernetes/pki/apiserver.crt",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		{
			name:           "kube-apiserver reading k8s cert - should not trigger",
			execPath:       "/usr/bin/kube-apiserver",
			pathname:       "/etc/kubernetes/pki/apiserver.crt",
			flags:          0, // O_RDONLY
			expectedOutput: false,
		},
		{
			name:           "malicious process writing k8s cert - should not trigger (not a read)",
			execPath:       "/usr/bin/malicious",
			pathname:       "/etc/kubernetes/pki/apiserver.crt",
			flags:          1, // O_WRONLY
			expectedOutput: false,
		},
		// Note: non-k8s file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &KubernetesCertificateTheft{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_file_open,
				Name: "security_file_open",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: tc.execPath},
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

func TestKubernetesCertificateTheft_Rename(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		oldPath        string
		expectedOutput bool
	}{
		{
			name:           "rename k8s cert - should detect",
			oldPath:        "/etc/kubernetes/pki/apiserver.key",
			expectedOutput: true,
		},
		// Note: non-k8s file test removed - DataFilter would prevent this event from reaching OnEvent
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &KubernetesCertificateTheft{}
			err := detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_security_inode_rename,
				Name: "security_inode_rename",
				Workload: &v1beta1.Workload{
					Process: &v1beta1.Process{
						Executable: &v1beta1.Executable{Path: "/usr/bin/mv"},
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("old_path", tc.oldPath),
				},
			}

			output, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedOutput {
				assert.Len(t, output, 1, "Expected detection for rename of k8s cert")
			} else {
				assert.Len(t, output, 0, "Expected no detection for rename of non-k8s file")
			}
		})
	}
}
