package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrichmentConfig_flags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   EnrichmentConfig
		expected []string
	}{
		{
			name:     "empty config",
			config:   EnrichmentConfig{},
			expected: []string{},
		},
		{
			name: "container enabled only",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
				},
			},
			expected: []string{
				"container.enabled",
			},
		},
		{
			name: "container sockets only",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
			},
			expected: []string{
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
			},
		},
		{
			name: "container cgroup path",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Cgroup: ContainerCgroupConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
			},
			expected: []string{
				"container.cgroup.path=/host/sys/fs/cgroup",
			},
		},
		{
			name: "container cgroup force enabled",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Cgroup: ContainerCgroupConfig{
						Force: true,
					},
				},
			},
			expected: []string{
				"container.cgroup.force",
			},
		},
		{
			name: "resolve-fd enabled",
			config: EnrichmentConfig{
				ResolveFd: true,
			},
			expected: []string{
				"resolve-fd",
			},
		},
		{
			name: "exec-hash enabled",
			config: EnrichmentConfig{
				ExecHash: ExecHashConfig{
					Enabled: true,
				},
			},
			expected: []string{
				"exec-hash.enabled",
			},
		},
		{
			name: "exec-hash mode",
			config: EnrichmentConfig{
				ExecHash: ExecHashConfig{
					Mode: "dev-inode",
				},
			},
			expected: []string{
				"exec-hash.mode=dev-inode",
			},
		},
		{
			name: "user-stack-trace enabled",
			config: EnrichmentConfig{
				UserStackTrace: true,
			},
			expected: []string{
				"user-stack-trace",
			},
		},
		{
			name: "all options enabled",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
					Cgroup: ContainerCgroupConfig{
						Path:  "/host/sys/fs/cgroup",
						Force: true,
					},
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
				ResolveFd: true,
				ExecHash: ExecHashConfig{
					Enabled: true,
					Mode:    "dev-inode",
				},
				UserStackTrace: true,
			},
			expected: []string{
				"container.enabled",
				"container.cgroup.path=/host/sys/fs/cgroup",
				"container.cgroup.force",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd",
				"exec-hash.enabled",
				"exec-hash.mode=dev-inode",
				"user-stack-trace",
			},
		},
		{
			name: "partial container configuration",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true,
					DockerSocket: "/var/run/docker.sock",
				},
				ResolveFd: true,
			},
			expected: []string{
				"container.enabled",
				"container.docker.socket=/var/run/docker.sock",
				"resolve-fd",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.flags()
			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
		})
	}
}

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
			testName:       "default values",
			flags:          []string{},
			expectedReturn: EnrichmentConfig{},
		},
		// valid single container flags
		{
			testName: "valid container.enabled",
			flags:    []string{"container.enabled"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
				},
			},
		},
		{
			testName: "valid container.cgroup.path",
			flags:    []string{"container.cgroup.path=/host/sys/fs/cgroup"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Cgroup: ContainerCgroupConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
			},
		},
		{
			testName: "valid container.cgroup.force",
			flags:    []string{"container.cgroup.force"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Cgroup: ContainerCgroupConfig{
						Force: true,
					},
				},
			},
		},
		{
			testName: "valid container.docker.socket",
			flags:    []string{"container.docker.socket=/var/run/docker.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					DockerSocket: "/var/run/docker.sock",
				},
			},
		},
		{
			testName: "valid container.containerd.socket",
			flags:    []string{"container.containerd.socket=/var/run/containerd/containerd.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					ContainerdSocket: "/var/run/containerd/containerd.sock",
				},
			},
		},
		{
			testName: "valid container.crio.socket",
			flags:    []string{"container.crio.socket=/var/run/crio/crio.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					CrioSocket: "/var/run/crio/crio.sock",
				},
			},
		},
		{
			testName: "valid container.podman.socket",
			flags:    []string{"container.podman.socket=/var/run/podman/podman.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					PodmanSocket: "/var/run/podman/podman.sock",
				},
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
				ExecHash: ExecHashConfig{
					Enabled: true,
				},
			},
		},
		{
			testName: "valid exec-hash.mode",
			flags:    []string{"exec-hash.mode=dev-inode"},
			expectedReturn: EnrichmentConfig{
				ExecHash: ExecHashConfig{
					Mode: "dev-inode",
				},
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
				Container: ContainerEnrichmentConfig{
					Enabled:      true,
					DockerSocket: "/var/run/docker.sock",
					Cgroup: ContainerCgroupConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
			},
		},
		{
			testName: "valid multiple socket flags",
			flags:    []string{"container.docker.socket=/var/run/docker.sock", "container.containerd.socket=/var/run/containerd/containerd.sock", "container.crio.socket=/var/run/crio/crio.sock", "container.podman.socket=/var/run/podman/podman.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"container.enabled", "container.cgroup.path=/host/sys/fs/cgroup", "container.cgroup.force", "container.docker.socket=/var/run/docker.sock", "container.containerd.socket=/var/run/containerd/containerd.sock", "container.crio.socket=/var/run/crio/crio.sock", "container.podman.socket=/var/run/podman/podman.sock", "resolve-fd", "exec-hash.enabled", "exec-hash.mode=dev-inode", "user-stack-trace"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
					Cgroup: ContainerCgroupConfig{
						Path:  "/host/sys/fs/cgroup",
						Force: true,
					},
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
				ResolveFd: true,
				ExecHash: ExecHashConfig{
					Enabled: true,
					Mode:    "dev-inode",
				},
				UserStackTrace: true,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"user-stack-trace", "container.cgroup.path=/host/sys/fs/cgroup", "exec-hash.mode=sha256", "container.enabled", "resolve-fd"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
					Cgroup: ContainerCgroupConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
				ResolveFd: true,
				ExecHash: ExecHashConfig{
					Mode: "sha256",
				},
				UserStackTrace: true,
			},
		},
		// valid duplicate flags (last one wins for strings, but bools always set to true)
		{
			testName: "valid duplicate flags",
			flags:    []string{"container.docker.socket=/var/run/docker.sock", "container.docker.socket=/var/run/docker2.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					DockerSocket: "/var/run/docker2.sock",
				},
			},
		},
		// invalid flag format
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"container.enabledtrue"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container.enabledtrue"),
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"container.enabled="},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container.enabled="),
		},
		{
			testName:       "invalid boolean flag with =true",
			flags:          []string{"container.enabled=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container.enabled=true"),
		},
		{
			testName:       "invalid boolean flag resolve-fd with =true",
			flags:          []string{"resolve-fd=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("resolve-fd=true"),
		},
		{
			testName:       "invalid boolean flag exec-hash.enabled with =true",
			flags:          []string{"exec-hash.enabled=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("exec-hash.enabled=true"),
		},
		{
			testName:       "invalid boolean flag user-stack-trace with =true",
			flags:          []string{"user-stack-trace=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("user-stack-trace=true"),
		},
		{
			testName:       "invalid boolean flag container.cgroup.force with =true",
			flags:          []string{"container.cgroup.force=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container.cgroup.force=true"),
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("invalid-flag"),
		},
		{
			testName:       "invalid flag name with typo",
			flags:          []string{"container.enable=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container.enable"),
		},
		// valid edge cases
		{
			testName: "valid empty string values",
			flags:    []string{"container.cgroup.path=", "exec-hash.mode="},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Cgroup: ContainerCgroupConfig{
						Path: "",
					},
				},
				ExecHash: ExecHashConfig{
					Mode: "",
				},
			},
		},
		{
			testName: "valid long paths",
			flags:    []string{"container.docker.socket=/very/long/path/to/docker/socket/file.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					DockerSocket: "/very/long/path/to/docker/socket/file.sock",
				},
			},
		},
		{
			testName: "valid relative paths",
			flags:    []string{"container.docker.socket=./docker.sock", "container.cgroup.path=../cgroup"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					DockerSocket: "./docker.sock",
					Cgroup: ContainerCgroupConfig{
						Path: "../cgroup",
					},
				},
			},
		},
		{
			testName: "valid exec-hash.mode values",
			flags:    []string{"exec-hash.mode=sha256"},
			expectedReturn: EnrichmentConfig{
				ExecHash: ExecHashConfig{
					Mode: "sha256",
				},
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"container.enabled", "invalid-flag=value"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("invalid-flag"),
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"container.enabled", "resolve"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("resolve"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			enrichment, err := PrepareEnrichment(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, "flags.PrepareEnrichment: "+tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.Container.Enabled, enrichment.Container.Enabled)
				assert.Equal(t, tc.expectedReturn.Container.Cgroup.Path, enrichment.Container.Cgroup.Path)
				assert.Equal(t, tc.expectedReturn.Container.Cgroup.Force, enrichment.Container.Cgroup.Force)
				assert.Equal(t, tc.expectedReturn.Container.DockerSocket, enrichment.Container.DockerSocket)
				assert.Equal(t, tc.expectedReturn.Container.ContainerdSocket, enrichment.Container.ContainerdSocket)
				assert.Equal(t, tc.expectedReturn.Container.CrioSocket, enrichment.Container.CrioSocket)
				assert.Equal(t, tc.expectedReturn.Container.PodmanSocket, enrichment.Container.PodmanSocket)
				assert.Equal(t, tc.expectedReturn.ResolveFd, enrichment.ResolveFd)
				assert.Equal(t, tc.expectedReturn.ExecHash.Enabled, enrichment.ExecHash.Enabled)
				assert.Equal(t, tc.expectedReturn.ExecHash.Mode, enrichment.ExecHash.Mode)
				assert.Equal(t, tc.expectedReturn.UserStackTrace, enrichment.UserStackTrace)
			}
		})
	}
}
