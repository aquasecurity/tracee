package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareEnrichment(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn EnrichmentConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: EnrichmentConfig{
				ContainerEnabled:          false,
				ContainerCgroupPath:       "",
				ContainerDockerSocket:     "",
				ContainerContainerdSocket: "",
				ContainerCrioSocket:       "",
				ContainerPodmanSocket:     "",
				ResolveFd:                 false,
				ExecHashEnabled:           false,
				ExecHashMode:              "",
				UserStackTrace:            false,
			},
		},
		// valid single container flags
		{
			testName: "valid container.enabled",
			flags:    []string{"container.enabled"},
			expectedReturn: EnrichmentConfig{
				ContainerEnabled: true,
			},
		},
		{
			testName: "valid container.cgroup.path",
			flags:    []string{"container.cgroup.path=/host/sys/fs/cgroup"},
			expectedReturn: EnrichmentConfig{
				ContainerCgroupPath: "/host/sys/fs/cgroup",
			},
		},
		{
			testName: "valid container.docker.socket",
			flags:    []string{"container.docker.socket=/var/run/docker.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerDockerSocket: "/var/run/docker.sock",
			},
		},
		{
			testName: "valid container.containerd.socket",
			flags:    []string{"container.containerd.socket=/var/run/containerd/containerd.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerContainerdSocket: "/var/run/containerd/containerd.sock",
			},
		},
		{
			testName: "valid container.crio.socket",
			flags:    []string{"container.crio.socket=/var/run/crio/crio.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerCrioSocket: "/var/run/crio/crio.sock",
			},
		},
		{
			testName: "valid container.podman.socket",
			flags:    []string{"container.podman.socket=/var/run/podman/podman.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerPodmanSocket: "/var/run/podman/podman.sock",
			},
		},
		// valid single resolve-fd flags
		{
			testName: "valid resolve-fd",
			flags:    []string{"resolve-fd"},
			expectedReturn: EnrichmentConfig{
				ResolveFd: true,
			},
		},
		// valid single exec-hash flags
		{
			testName: "valid exec-hash.enabled",
			flags:    []string{"exec-hash.enabled"},
			expectedReturn: EnrichmentConfig{
				ExecHashEnabled: true,
			},
		},
		{
			testName: "valid exec-hash.mode",
			flags:    []string{"exec-hash.mode=dev-inode"},
			expectedReturn: EnrichmentConfig{
				ExecHashMode: "dev-inode",
			},
		},
		// valid single user-stack-trace flags
		{
			testName: "valid user-stack-trace",
			flags:    []string{"user-stack-trace"},
			expectedReturn: EnrichmentConfig{
				UserStackTrace: true,
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple container flags",
			flags:    []string{"container.enabled", "container.docker.socket=/var/run/docker.sock", "container.cgroup.path=/host/sys/fs/cgroup"},
			expectedReturn: EnrichmentConfig{
				ContainerEnabled:      true,
				ContainerDockerSocket: "/var/run/docker.sock",
				ContainerCgroupPath:   "/host/sys/fs/cgroup",
			},
		},
		{
			testName: "valid multiple socket flags",
			flags:    []string{"container.docker.socket=/var/run/docker.sock", "container.containerd.socket=/var/run/containerd/containerd.sock", "container.crio.socket=/var/run/crio/crio.sock", "container.podman.socket=/var/run/podman/podman.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerDockerSocket:     "/var/run/docker.sock",
				ContainerContainerdSocket: "/var/run/containerd/containerd.sock",
				ContainerCrioSocket:       "/var/run/crio/crio.sock",
				ContainerPodmanSocket:     "/var/run/podman/podman.sock",
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"container.enabled", "container.cgroup.path=/host/sys/fs/cgroup", "container.docker.socket=/var/run/docker.sock", "container.containerd.socket=/var/run/containerd/containerd.sock", "container.crio.socket=/var/run/crio/crio.sock", "container.podman.socket=/var/run/podman/podman.sock", "resolve-fd", "exec-hash.enabled", "exec-hash.mode=dev-inode", "user-stack-trace"},
			expectedReturn: EnrichmentConfig{
				ContainerEnabled:          true,
				ContainerCgroupPath:       "/host/sys/fs/cgroup",
				ContainerDockerSocket:     "/var/run/docker.sock",
				ContainerContainerdSocket: "/var/run/containerd/containerd.sock",
				ContainerCrioSocket:       "/var/run/crio/crio.sock",
				ContainerPodmanSocket:     "/var/run/podman/podman.sock",
				ResolveFd:                 true,
				ExecHashEnabled:           true,
				ExecHashMode:              "dev-inode",
				UserStackTrace:            true,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"user-stack-trace", "container.cgroup.path=/host/sys/fs/cgroup", "exec-hash.mode=sha256", "container.enabled", "resolve-fd"},
			expectedReturn: EnrichmentConfig{
				ContainerEnabled:    true,
				ContainerCgroupPath: "/host/sys/fs/cgroup",
				ExecHashMode:        "sha256",
				ResolveFd:           true,
				UserStackTrace:      true,
			},
		},
		// valid duplicate flags (last one wins for strings, but bools always set to true)
		{
			testName: "valid duplicate flags",
			flags:    []string{"container.docker.socket=/var/run/docker.sock", "container.docker.socket=/var/run/docker2.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerDockerSocket: "/var/run/docker2.sock",
			},
		},
		// invalid flag format
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"container.enabledtrue"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: container.enabledtrue, use 'trace man enrichment' for more info",
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"container.enabled="},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: container.enabled=, use 'trace man enrichment' for more info",
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: invalid-flag, use 'trace man enrichment' for more info",
		},
		{
			testName:       "invalid flag name with typo",
			flags:          []string{"container.enable=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: container.enable, use 'trace man enrichment' for more info",
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: , use 'trace man enrichment' for more info",
		},
		// valid edge cases
		{
			testName: "valid empty string values",
			flags:    []string{"container.cgroup.path=", "exec-hash.mode="},
			expectedReturn: EnrichmentConfig{
				ContainerCgroupPath: "",
				ExecHashMode:        "",
			},
		},
		{
			testName: "valid long paths",
			flags:    []string{"container.docker.socket=/very/long/path/to/docker/socket/file.sock"},
			expectedReturn: EnrichmentConfig{
				ContainerDockerSocket: "/very/long/path/to/docker/socket/file.sock",
			},
		},
		{
			testName: "valid relative paths",
			flags:    []string{"container.docker.socket=./docker.sock", "container.cgroup.path=../cgroup"},
			expectedReturn: EnrichmentConfig{
				ContainerDockerSocket: "./docker.sock",
				ContainerCgroupPath:   "../cgroup",
			},
		},
		{
			testName: "valid exec-hash.mode values",
			flags:    []string{"exec-hash.mode=sha256"},
			expectedReturn: EnrichmentConfig{
				ExecHashMode: "sha256",
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"container.enabled", "invalid-flag=value"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: invalid-flag, use 'trace man enrichment' for more info",
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"container.enabled", "resolve"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "flags.PrepareEnrichment: invalid enrichment flag: resolve, use 'trace man enrichment' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			enrichment, err := PrepareEnrichment(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.ContainerEnabled, enrichment.ContainerEnabled)
				assert.Equal(t, tc.expectedReturn.ContainerCgroupPath, enrichment.ContainerCgroupPath)
				assert.Equal(t, tc.expectedReturn.ContainerDockerSocket, enrichment.ContainerDockerSocket)
				assert.Equal(t, tc.expectedReturn.ContainerContainerdSocket, enrichment.ContainerContainerdSocket)
				assert.Equal(t, tc.expectedReturn.ContainerCrioSocket, enrichment.ContainerCrioSocket)
				assert.Equal(t, tc.expectedReturn.ContainerPodmanSocket, enrichment.ContainerPodmanSocket)
				assert.Equal(t, tc.expectedReturn.ResolveFd, enrichment.ResolveFd)
				assert.Equal(t, tc.expectedReturn.ExecHashEnabled, enrichment.ExecHashEnabled)
				assert.Equal(t, tc.expectedReturn.ExecHashMode, enrichment.ExecHashMode)
				assert.Equal(t, tc.expectedReturn.UserStackTrace, enrichment.UserStackTrace)
			}
		})
	}
}
