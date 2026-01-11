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
				"exec-hash",
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
				"exec-hash",
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
			name: "exec-env enabled",
			config: EnrichmentConfig{
				ExecEnv: true,
			},
			expected: []string{
				"exec-env",
			},
		},
		{
			name: "parse-arguments enabled",
			config: EnrichmentConfig{
				ParseArguments: true,
			},
			expected: []string{
				"parse-arguments",
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
				ResolveFd: true,
				ExecHash: ExecHashConfig{
					Enabled: true,
					Mode:    "dev-inode",
				},
				UserStackTrace: true,
				ExecEnv:        true,
				ParseArguments: true,
			},
			expected: []string{
				"container",
				"container.cgroupfs.path=/host/sys/fs/cgroup",
				"container.cgroupfs.force",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd",
				"exec-env",
				"exec-hash",
				"exec-hash.mode=dev-inode",
				"user-stack-trace",
				"parse-arguments",
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
				"container",
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
			testName: "valid exec-hash",
			flags:    []string{"exec-hash"},
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
					Enabled: true, // Setting mode enables exec-hash
					Mode:    "dev-inode",
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
		// valid single exec-env flags
		{
			testName: "valid exec-env",
			flags:    []string{"exec-env"},
			expectedReturn: EnrichmentConfig{
				ExecEnv: true,
			},
		},
		// valid single parse-arguments flags
		{
			testName: "valid parse-arguments",
			flags:    []string{"parse-arguments"},
			expectedReturn: EnrichmentConfig{
				ParseArguments: true,
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
			flags:    []string{"container", "container.cgroupfs.path=/host/sys/fs/cgroup", "container.cgroupfs.force", "container.docker.socket=/var/run/docker.sock", "container.containerd.socket=/var/run/containerd/containerd.sock", "container.crio.socket=/var/run/crio/crio.sock", "container.podman.socket=/var/run/podman/podman.sock", "resolve-fd", "exec-env", "exec-hash", "exec-hash.mode=dev-inode", "user-stack-trace", "parse-arguments"},
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
				ResolveFd:      true,
				ExecEnv:        true,
				ParseArguments: true,
				ExecHash: ExecHashConfig{
					Enabled: true,
					Mode:    "dev-inode",
				},
				UserStackTrace: true,
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"user-stack-trace", "container.cgroupfs.path=/host/sys/fs/cgroup", "exec-hash.mode=sha256", "container", "resolve-fd"},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true, // Setting cgroupfs.path enables container
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "/host/sys/fs/cgroup",
					},
				},
				ResolveFd: true,
				ExecHash: ExecHashConfig{
					Enabled: true, // Setting mode enables exec-hash
					Mode:    "sha256",
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
			testName:       "invalid boolean flag resolve-fd with =true",
			flags:          []string{"resolve-fd=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("resolve-fd=true"),
		},
		{
			testName:       "invalid boolean flag exec-hash with =true",
			flags:          []string{"exec-hash=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("exec-hash=true"),
		},
		{
			testName:       "invalid boolean flag user-stack-trace with =true",
			flags:          []string{"user-stack-trace=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("user-stack-trace=true"),
		},
		{
			testName:       "invalid boolean flag exec-env with =true",
			flags:          []string{"exec-env=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("exec-env=true"),
		},
		{
			testName:       "invalid boolean flag parse-arguments with =true",
			flags:          []string{"parse-arguments=true"},
			expectedReturn: EnrichmentConfig{},
			expectedError:  invalidEnrichmentFlagError("parse-arguments=true"),
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
			flags:    []string{"container.cgroupfs.path=", "exec-hash.mode="},
			expectedReturn: EnrichmentConfig{
				Container: ContainerEnrichmentConfig{
					Enabled: true, // Setting cgroupfs.path enables container
					Cgroupfs: ContainerCgroupfsConfig{
						Path: "",
					},
				},
				ExecHash: ExecHashConfig{
					Enabled: true, // Setting mode enables exec-hash
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
			testName: "valid exec-hash.mode values",
			flags:    []string{"exec-hash.mode=sha256"},
			expectedReturn: EnrichmentConfig{
				ExecHash: ExecHashConfig{
					Enabled: true, // Setting mode enables exec-hash
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
				assert.Equal(t, tc.expectedReturn.ResolveFd, enrichment.ResolveFd)
				assert.Equal(t, tc.expectedReturn.ExecEnv, enrichment.ExecEnv)
				assert.Equal(t, tc.expectedReturn.ParseArguments, enrichment.ParseArguments)
				assert.Equal(t, tc.expectedReturn.ExecHash.Enabled, enrichment.ExecHash.Enabled)
				assert.Equal(t, tc.expectedReturn.ExecHash.Mode, enrichment.ExecHash.Mode)
				assert.Equal(t, tc.expectedReturn.UserStackTrace, enrichment.UserStackTrace)
			}
		})
	}
}
