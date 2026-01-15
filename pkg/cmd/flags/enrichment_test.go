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
				"container",
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
				"container",
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
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
			},
			expected: []string{
				"container",
				"container.cgroupfs.path=/host/sys/fs/cgroup",
			},
		},
		{
			name: "container cgroup force with path",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Cgroupfs: ContainerCgroupfsConfig{
						Path:  "/host/sys/fs/cgroup",
						Force: true,
					},
				},
			},
			expected: []string{
				"container",
				"container.cgroupfs.path=/host/sys/fs/cgroup",
				"container.cgroupfs.force",
			},
		},
		{
			name: "fd-paths enabled",
			config: EnrichmentConfig{
				FdPaths: true,
			},
			expected: []string{
				"fd-paths",
			},
		},
		{
			name: "executable-hash enabled",
			config: EnrichmentConfig{
				ExecutableHash: ExecutableHashConfig{
					Enabled: true,
				},
			},
			expected: []string{
				"executable-hash",
			},
		},
		{
			name: "executable-hash mode",
			config: EnrichmentConfig{
				ExecutableHash: ExecutableHashConfig{
					Mode: "dev-inode",
				},
			},
			expected: []string{
				"executable-hash",
				"executable-hash.mode=dev-inode",
			},
		},
		{
			name: "user-stack enabled",
			config: EnrichmentConfig{
				UserStack: true,
			},
			expected: []string{
				"user-stack",
			},
		},
		{
			name: "environment enabled",
			config: EnrichmentConfig{
				Environment: true,
			},
			expected: []string{
				"environment",
			},
		},
		{
			name: "decoded-data enabled",
			config: EnrichmentConfig{
				DecodedData: true,
			},
			expected: []string{
				"decoded-data",
			},
		},
		{
			name: "all options enabled",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
					Cgroupfs: ContainerCgroupfsConfig{
						Path:  "/host/sys/fs/cgroup",
						Force: true,
					},
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
				FdPaths: true,
				ExecutableHash: ExecutableHashConfig{
					Enabled: true,
					Mode:    "dev-inode",
				},
				UserStack:   true,
				Environment: true,
				DecodedData: true,
			},
			expected: []string{
				"container",
				"container.cgroupfs.path=/host/sys/fs/cgroup",
				"container.cgroupfs.force",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"fd-paths",
				"environment",
				"executable-hash",
				"executable-hash.mode=dev-inode",
				"user-stack",
				"decoded-data",
			},
		},
		{
			name: "partial container configuration",
			config: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true,
					DockerSocket: "/var/run/docker.sock",
				},
				FdPaths: true,
			},
			expected: []string{
				"container",
				"container.docker.socket=/var/run/docker.sock",
				"fd-paths",
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
			testName: "valid container",
			flags:    []string{"container"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
				},
			},
		},
		{
			testName: "valid container.cgroupfs.path",
			flags:    []string{"container.cgroupfs.path=/host/sys/fs/cgroup"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true, // Setting cgroupfs.path enables container
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
			},
		},
		{
			testName:       "invalid container.cgroupfs.force without path",
			flags:          []string{"container.cgroupfs.force"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  "container.cgroupfs.force requires container.cgroupfs.path to be set",
		},
		{
			testName: "valid container.cgroupfs.force with path",
			flags:    []string{"container.cgroupfs.path=/host/sys/fs/cgroup", "container.cgroupfs.force"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true, // Setting cgroupfs.path enables container
					Cgroupfs: ContainerCgroupfsConfig{
						Path:  "/host/sys/fs/cgroup",
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
					Enabled:      true, // Setting docker.socket enables container
					DockerSocket: "/var/run/docker.sock",
				},
			},
		},
		{
			testName: "valid container.containerd.socket",
			flags:    []string{"container.containerd.socket=/var/run/containerd/containerd.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:          true, // Setting containerd.socket enables container
					ContainerdSocket: "/var/run/containerd/containerd.sock",
				},
			},
		},
		{
			testName: "valid container.crio.socket",
			flags:    []string{"container.crio.socket=/var/run/crio/crio.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:    true, // Setting crio.socket enables container
					CrioSocket: "/var/run/crio/crio.sock",
				},
			},
		},
		{
			testName: "valid container.podman.socket",
			flags:    []string{"container.podman.socket=/var/run/podman/podman.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true, // Setting podman.socket enables container
					PodmanSocket: "/var/run/podman/podman.sock",
				},
			},
		},
		// valid single fd-paths flags
		{
			testName: "valid fd-paths",
			flags:    []string{"fd-paths"},
			expectedReturn: EnrichmentConfig{
				FdPaths: true,
			},
		},
		// valid single executable-hash flags
		{
			testName: "valid executable-hash",
			flags:    []string{"executable-hash"},
			expectedReturn: EnrichmentConfig{
				ExecutableHash: ExecutableHashConfig{
					Enabled: true,
				},
			},
		},
		{
			testName: "valid executable-hash.mode",
			flags:    []string{"executable-hash.mode=dev-inode"},
			expectedReturn: EnrichmentConfig{
				ExecutableHash: ExecutableHashConfig{
					Enabled: true, // Setting mode enables executable-hash
					Mode:    "dev-inode",
				},
			},
		},
		// valid single user-stack flags
		{
			testName: "valid user-stack",
			flags:    []string{"user-stack"},
			expectedReturn: EnrichmentConfig{
				UserStack: true,
			},
		},
		// valid single environment flags
		{
			testName: "valid environment",
			flags:    []string{"environment"},
			expectedReturn: EnrichmentConfig{
				Environment: true,
			},
		},
		// valid single decoded-data flags
		{
			testName: "valid decoded-data",
			flags:    []string{"decoded-data"},
			expectedReturn: EnrichmentConfig{
				DecodedData: true,
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple container flags",
			flags:    []string{"container", "container.docker.socket=/var/run/docker.sock", "container.cgroupfs.path=/host/sys/fs/cgroup"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true,
					DockerSocket: "/var/run/docker.sock",
					Cgroupfs: ContainerCgroupfsConfig{
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
					Enabled:          true, // Setting any socket enables container
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"container", "container.cgroupfs.path=/host/sys/fs/cgroup", "container.cgroupfs.force", "container.docker.socket=/var/run/docker.sock", "container.containerd.socket=/var/run/containerd/containerd.sock", "container.crio.socket=/var/run/crio/crio.sock", "container.podman.socket=/var/run/podman/podman.sock", "fd-paths", "environment", "executable-hash", "executable-hash.mode=dev-inode", "user-stack", "decoded-data"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true,
					Cgroupfs: ContainerCgroupfsConfig{
						Path:  "/host/sys/fs/cgroup",
						Force: true,
					},
					DockerSocket:     "/var/run/docker.sock",
					ContainerdSocket: "/var/run/containerd/containerd.sock",
					CrioSocket:       "/var/run/crio/crio.sock",
					PodmanSocket:     "/var/run/podman/podman.sock",
				},
				FdPaths:     true,
				Environment: true,
				DecodedData: true,
				ExecutableHash: ExecutableHashConfig{
					Enabled: true,
					Mode:    "dev-inode",
				},
				UserStack: true,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"user-stack", "container.cgroupfs.path=/host/sys/fs/cgroup", "executable-hash.mode=sha256", "container", "fd-paths"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true, // Setting cgroupfs.path enables container
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
				FdPaths: true,
				ExecutableHash: ExecutableHashConfig{
					Enabled: true, // Setting mode enables executable-hash
					Mode:    "sha256",
				},
				UserStack: true,
			},
		},
		// valid duplicate flags (last one wins for strings, but bools always set to true)
		{
			testName: "valid duplicate flags",
			flags:    []string{"container.docker.socket=/var/run/docker.sock", "container.docker.socket=/var/run/docker2.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true, // Setting docker.socket enables container
					DockerSocket: "/var/run/docker2.sock",
				},
			},
		},
		// invalid flag format
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"containertrue"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("containertrue"),
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"container="},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container="),
		},
		{
			testName:       "invalid boolean flag with =true",
			flags:          []string{"container=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container=true"),
		},
		{
			testName:       "invalid boolean flag fd-paths with =true",
			flags:          []string{"fd-paths=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("fd-paths=true"),
		},
		{
			testName:       "invalid boolean flag executable-hash with =true",
			flags:          []string{"executable-hash=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("executable-hash=true"),
		},
		{
			testName:       "invalid boolean flag user-stack with =true",
			flags:          []string{"user-stack=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("user-stack=true"),
		},
		{
			testName:       "invalid boolean flag environment with =true",
			flags:          []string{"environment=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("environment=true"),
		},
		{
			testName:       "invalid boolean flag decoded-data with =true",
			flags:          []string{"decoded-data=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("decoded-data=true"),
		},
		{
			testName:       "invalid boolean flag container.cgroupfs.force with =true",
			flags:          []string{"container.cgroupfs.force=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("container.cgroupfs.force=true"),
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
			flags:    []string{"container.cgroupfs.path=", "executable-hash.mode="},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true, // Setting cgroupfs.path enables container
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "",
					},
				},
				ExecutableHash: ExecutableHashConfig{
					Enabled: true, // Setting mode enables executable-hash
					Mode:    "",
				},
			},
		},
		{
			testName: "valid long paths",
			flags:    []string{"container.docker.socket=/very/long/path/to/docker/socket/file.sock"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true, // Setting docker.socket enables container
					DockerSocket: "/very/long/path/to/docker/socket/file.sock",
				},
			},
		},
		{
			testName: "valid relative paths",
			flags:    []string{"container.docker.socket=./docker.sock", "container.cgroupfs.path=../cgroup"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled:      true, // Setting docker.socket or cgroupfs.path enables container
					DockerSocket: "./docker.sock",
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "../cgroup",
					},
				},
			},
		},
		{
			testName: "valid executable-hash.mode values",
			flags:    []string{"executable-hash.mode=sha256"},
			expectedReturn: EnrichmentConfig{
				ExecutableHash: ExecutableHashConfig{
					Enabled: true, // Setting mode enables executable-hash
					Mode:    "sha256",
				},
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"container", "invalid-flag=value"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("invalid-flag"),
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"container", "resolve"},
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
				assert.Equal(t, tc.expectedReturn.Container.Cgroupfs.Path, enrichment.Container.Cgroupfs.Path)
				assert.Equal(t, tc.expectedReturn.Container.Cgroupfs.Force, enrichment.Container.Cgroupfs.Force)
				assert.Equal(t, tc.expectedReturn.Container.DockerSocket, enrichment.Container.DockerSocket)
				assert.Equal(t, tc.expectedReturn.Container.ContainerdSocket, enrichment.Container.ContainerdSocket)
				assert.Equal(t, tc.expectedReturn.Container.CrioSocket, enrichment.Container.CrioSocket)
				assert.Equal(t, tc.expectedReturn.Container.PodmanSocket, enrichment.Container.PodmanSocket)
				assert.Equal(t, tc.expectedReturn.FdPaths, enrichment.FdPaths)
				assert.Equal(t, tc.expectedReturn.Environment, enrichment.Environment)
				assert.Equal(t, tc.expectedReturn.DecodedData, enrichment.DecodedData)
				assert.Equal(t, tc.expectedReturn.ExecutableHash.Enabled, enrichment.ExecutableHash.Enabled)
				assert.Equal(t, tc.expectedReturn.ExecutableHash.Mode, enrichment.ExecutableHash.Mode)
				assert.Equal(t, tc.expectedReturn.UserStack, enrichment.UserStack)
			}
		})
	}
}
