package flags

import (
	"log"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestGetFlagsFromViper tests the GetFlagsFromViper function using a global
// viper instance. It tests all keys that are supported by the function for
// both structured and cli flags.
func TestGetFlagsFromViper(t *testing.T) {
	// Cannot run in parallel because of the global viper instance

	tests := []struct {
		name          string
		yamlContent   string
		key           string
		expectedFlags []string
	}{
		{
			name: "Test stores configuration (cli flags - process only)",
			yamlContent: `
stores:
    - process
    - process.source=events
    - process.max-processes=8192
    - process.max-threads=4096
`,
			key: "stores",
			expectedFlags: []string{
				"process",
				"process.source=events",
				"process.max-processes=8192",
				"process.max-threads=4096",
			},
		},
		{
			name: "Test stores configuration (structured flags - process only)",
			yamlContent: `
stores:
    process:
        enabled: true
        source: events
        max-processes: 8192
        max-threads: 4096
`,
			key: "stores",
			expectedFlags: []string{
				"process",
				"process.source=events",
				"process.max-processes=8192",
				"process.max-threads=4096",
			},
		},
		{
			name: "Test stores configuration (cli flags - DNS only)",
			yamlContent: `
stores:
    - dns
    - dns.max-entries=1024
`,
			key: "stores",
			expectedFlags: []string{
				"dns",
				"dns.max-entries=1024",
			},
		},
		{
			name: "Test stores configuration (structured flags - DNS only)",
			yamlContent: `
stores:
    dns:
        enabled: true
        max-entries: 1024
`,
			key: "stores",
			expectedFlags: []string{
				"dns",
				"dns.max-entries=1024",
			},
		},
		{
			name: "Test stores configuration (cli flags - all options)",
			yamlContent: `
stores:
    - dns
    - dns.max-entries=2048
    - process
    - process.source=both
    - process.max-processes=8192
    - process.max-threads=4096
    - process.use-procfs
`,
			key: "stores",
			expectedFlags: []string{
				"dns",
				"dns.max-entries=2048",
				"process",
				"process.source=both",
				"process.max-processes=8192",
				"process.max-threads=4096",
				"process.use-procfs",
			},
		},
		{
			name: "Test stores configuration (structured flags - all options)",
			yamlContent: `
stores:
    dns:
        enabled: true
        max-entries: 2048
    process:
        enabled: true
        source: both
        max-processes: 8192
        max-threads: 4096
        use-procfs: true
`,
			key: "stores",
			expectedFlags: []string{
				"dns",
				"dns.max-entries=2048",
				"process",
				"process.source=both",
				"process.max-processes=8192",
				"process.max-threads=4096",
				"process.use-procfs",
			},
		},
		{
			name: "Test capabilities configuration (cli flags)",
			yamlContent: `
capabilities:
    - bypass=false
    - add=CAP_NET_ADMIN
    - add=CAP_SYS_ADMIN
    - drop=CAP_NET_RAW
    - drop=CAP_DAC_OVERRIDE
`,
			key: "capabilities",
			expectedFlags: []string{
				"bypass=false",
				"add=CAP_NET_ADMIN",
				"add=CAP_SYS_ADMIN",
				"drop=CAP_NET_RAW",
				"drop=CAP_DAC_OVERRIDE",
			},
		},
		{
			name: "Test capabilities configuration (structured flags)",
			yamlContent: `
capabilities:
    bypass: false
    add:
        - CAP_NET_ADMIN
        - CAP_SYS_ADMIN
    drop:
        - CAP_NET_RAW
        - CAP_DAC_OVERRIDE
`,
			key: "capabilities",
			expectedFlags: []string{
				"bypass=false",
				"add=CAP_NET_ADMIN",
				"add=CAP_SYS_ADMIN",
				"drop=CAP_NET_RAW",
				"drop=CAP_DAC_OVERRIDE",
			},
		},
		{
			name: "Test log configuration (cli flags)",
			yamlContent: `
logging:
    - debug
    - file:/var/log/test.log
    - aggregate
    - aggregate.flush-interval=5s
    - filters.include.libbpf
    - filters.include.msg=msg1
    - filters.include.pkg=pkg1
    - filters.include.pkg=pkg2
    - filters.include.file=file1
    - filters.include.level=info
    - filters.include.regex=^regex.*
    - filters.exclude.msg=msg1
    - filters.exclude.pkg=pkg1
    - filters.exclude.file=file1
    - filters.exclude.file=file2
    - filters.exclude.level=info
    - filters.exclude.regex=^regex.*
`,
			key: "logging",
			expectedFlags: []string{
				"debug",
				"file:/var/log/test.log",
				"aggregate",
				"aggregate.flush-interval=5s",
				"filters.include.libbpf",
				"filters.include.msg=msg1",
				"filters.include.pkg=pkg1",
				"filters.include.pkg=pkg2",
				"filters.include.file=file1",
				"filters.include.level=info",
				"filters.include.regex=^regex.*",
				"filters.exclude.msg=msg1",
				"filters.exclude.pkg=pkg1",
				"filters.exclude.file=file1",
				"filters.exclude.file=file2",
				"filters.exclude.level=info",
				"filters.exclude.regex=^regex.*",
			},
		},
		{
			name: "Test log configuration (structured flags)",
			yamlContent: `
logging:
    level: debug
    file: /var/log/test.log
    aggregate:
        flush-interval: 5s
    filters:
        include:
            libbpf: true
            msg:
                - msg1
            pkg:
                - pkg1
                - pkg2
            file:
                - file1
            level:
                - info
            regex:
                - ^regex.*
        exclude:
            msg:
                - msg1
            pkg:
                - pkg1
            file:
                - file1
                - file2
            level:
                - info
            regex:
                - ^regex.*
`,
			key: "logging",
			expectedFlags: []string{
				"level=debug",
				"file=/var/log/test.log",
				"aggregate",
				"aggregate.flush-interval=5s",
				"filters.include.libbpf",
				"filters.include.msg=msg1",
				"filters.include.pkg=pkg1",
				"filters.include.pkg=pkg2",
				"filters.include.file=file1",
				"filters.include.level=info",
				"filters.include.regex=^regex.*",
				"filters.exclude.msg=msg1",
				"filters.exclude.pkg=pkg1",
				"filters.exclude.file=file1",
				"filters.exclude.file=file2",
				"filters.exclude.level=info",
				"filters.exclude.regex=^regex.*",
			},
		},
		{
			name: "Test output configuration (cli flags)",
			yamlContent: `
output:
    - none
    - option:stack-addresses
    - option:exec-env
    - option:exec-hash=dev-inode
    - option:parse-arguments
    - option:parse-arguments-fds
    - option:sort-events
    - table:file1
    - json:file2    
    - gotemplate=template1:file3,file4    
`,
			key: "output",
			expectedFlags: []string{
				"none",
				"option:stack-addresses",
				"option:exec-env",
				"option:exec-hash=dev-inode",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
				"table:file1",
				"json:file2",
				"gotemplate=template1:file3,file4",
			},
		},
		{
			name: "Test output configuration (config file)",
			yamlContent: `
output:
    destinations:
    - name: d1
      type: file
      format: json
      path: stdout
    - name: d2
      type: webhook
      format: json
      url: http://localhost:8080
    streams:
    - name: s1
      destinations:
      - d1
      buffer:
        size: 1024
        mode: drop
      filters:
        events:
        - e1
        policies:
        - p1
`,
			key: "output",
			expectedFlags: []string{
				"destinations.d1.type=file",
				"destinations.d1.format=json",
				"destinations.d1.path=stdout",
				"destinations.d2.type=webhook",
				"destinations.d2.format=json",
				"destinations.d2.url=http://localhost:8080",
				"streams.s1.destinations=d1",
				"streams.s1.buffer.size=1024",
				"streams.s1.buffer.mode=drop",
				"streams.s1.filters.events=e1",
				"streams.s1.filters.policies=p1",
			},
		},
		{
			name: "Test buffers configuration (cli flags)",
			yamlContent: `
buffers:
    - kernel.events=2048
    - kernel.artifacts=512
    - kernel.control-plane=256
    - pipeline=4000
`,
			key: "buffers",
			expectedFlags: []string{
				"kernel.events=2048",
				"kernel.artifacts=512",
				"kernel.control-plane=256",
				"pipeline=4000",
			},
		},
		{
			name: "Test buffers configuration (structured flags)",
			yamlContent: `
buffers:
    kernel:
        events: 2048
        artifacts: 512
        control-plane: 256
    pipeline: 4000
`,
			key: "buffers",
			expectedFlags: []string{
				"kernel.events=2048",
				"kernel.artifacts=512",
				"kernel.control-plane=256",
				"pipeline=4000",
			},
		},
		{
			name: "Test server configuration (cli flags)",
			yamlContent: `
server:
    - http-address=localhost:8080
    - grpc-address=unix:/var/run/tracee.sock
    - metrics
    - pprof
    - healthz
    - pyroscope`,
			key: "server",
			expectedFlags: []string{
				"grpc-address=unix:/var/run/tracee.sock",
				"http-address=localhost:8080",
				"metrics",
				"pprof",
				"healthz",
				"pyroscope",
			},
		},
		{
			name: "Test server configuration (structured flags)",
			yamlContent: `
server:
    http-address: localhost:8080
    grpc-address: unix:/var/run/tracee.sock
    metrics: true
    pprof: true
    healthz: true
    pyroscope: true`,
			key: "server",
			expectedFlags: []string{
				"http-address=localhost:8080",
				"grpc-address=unix:/var/run/tracee.sock",
				"metrics",
				"pprof",
				"healthz",
				"pyroscope",
			},
		},
		{
			name: "Test runtime configuration (cli flags)",
			yamlContent: `
runtime:
    - workdir=/tmp/tracee
`,
			key: "runtime",
			expectedFlags: []string{
				"workdir=/tmp/tracee",
			},
		},
		{
			name: "Test runtime configuration (structured flags)",
			yamlContent: `
runtime:
    workdir: /opt/tracee
`,
			key: "runtime",
			expectedFlags: []string{
				"workdir=/opt/tracee",
			},
		},
		{
			name: "Test enrich configuration (cli flags)",
			yamlContent: `
enrichment:
    - container
    - container.cgroupfs.path=/host/sys/fs/cgroup
    - container.cgroupfs.force
    - container.docker.socket=/var/run/docker.sock
    - container.containerd.socket=/var/run/containerd/containerd.sock
    - container.crio.socket=/var/run/crio/crio.sock
    - container.podman.socket=/var/run/podman/podman.sock
    - resolve-fd
    - exec-hash
    - exec-hash.mode=dev-inode
    - user-stack-trace
`,
			key: "enrichment",
			expectedFlags: []string{
				"container",
				"container.cgroupfs.path=/host/sys/fs/cgroup",
				"container.cgroupfs.force",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd",
				"exec-hash",
				"exec-hash.mode=dev-inode",
				"user-stack-trace",
			},
		},
		{
			name: "Test enrich configuration (structured flags)",
			yamlContent: `
enrichment:
    container:
        enabled: true
        cgroupfs:
            path: /host/sys/fs/cgroup
            force: true
        docker-socket: /var/run/docker.sock
        containerd-socket: /var/run/containerd/containerd.sock
        crio-socket: /var/run/crio/crio.sock
        podman-socket: /var/run/podman/podman.sock
    resolve-fd: true
    exec-hash:
        enabled: true
        mode: dev-inode
    user-stack-trace: true
`,
			key: "enrichment",
			expectedFlags: []string{
				"container",
				"container.cgroupfs.path=/host/sys/fs/cgroup",
				"container.cgroupfs.force",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd",
				"exec-hash",
				"exec-hash.mode=dev-inode",
				"user-stack-trace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot run in parallel because of the global viper instance

			viper.Reset() // Reset viper's state for each test case
			viper.SetConfigType("yaml")
			if err := viper.ReadConfig(strings.NewReader(tt.yamlContent)); err != nil {
				t.Fatalf("Error setting up viper: %v", err)
			}

			flags, err := GetFlagsFromViper(tt.key)
			assert.NoError(t, err)

			if len(flags) != len(tt.expectedFlags) {
				log.Printf("Expected %+v", tt.expectedFlags)
				log.Printf("Got %+v", flags)
				t.Fatalf("Expected %d flags, got %d flags", len(tt.expectedFlags), len(flags))
			}

			if !slicesEqualIgnoreOrder(flags, tt.expectedFlags) {
				t.Errorf("Expected %v, got %v", tt.expectedFlags, flags)
			}
		})
	}
}

//
// capabilities
//

func TestCapabilitiesConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   CapabilitiesConfig
		expected []string
	}{
		{
			name: "empty config",
			config: CapabilitiesConfig{
				Bypass: false,
				Add:    nil,
				Drop:   nil,
			},
			expected: []string{
				"bypass=false",
			},
		},
		{
			name: "bypass true",
			config: CapabilitiesConfig{
				Bypass: true,
				Add:    nil,
				Drop:   nil,
			},
			expected: []string{
				"bypass=true",
			},
		},
		{
			name: "only add capabilities",
			config: CapabilitiesConfig{
				Bypass: false,
				Add: []string{
					"CAP_NET_ADMIN",
					"CAP_SYS_ADMIN",
				},
				Drop: nil,
			},
			expected: []string{
				"bypass=false",
				"add=CAP_NET_ADMIN",
				"add=CAP_SYS_ADMIN",
			},
		},
		{
			name: "only drop capabilities",
			config: CapabilitiesConfig{
				Bypass: false,
				Add:    nil,
				Drop: []string{
					"CAP_NET_RAW",
					"CAP_DAC_OVERRIDE",
				},
			},
			expected: []string{
				"bypass=false",
				"drop=CAP_NET_RAW",
				"drop=CAP_DAC_OVERRIDE",
			},
		},
		{
			name: "add and drop capabilities",
			config: CapabilitiesConfig{
				Bypass: false,
				Add: []string{
					"CAP_NET_ADMIN",
				},
				Drop: []string{
					"CAP_NET_RAW",
				},
			},
			expected: []string{
				"bypass=false",
				"add=CAP_NET_ADMIN",
				"drop=CAP_NET_RAW",
			},
		},
		{
			name: "bypass with capabilities",
			config: CapabilitiesConfig{
				Bypass: true,
				Add: []string{
					"CAP_NET_ADMIN",
				},
				Drop: []string{
					"CAP_NET_RAW",
				},
			},
			expected: []string{
				"bypass=true",
				"add=CAP_NET_ADMIN",
				"drop=CAP_NET_RAW",
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

//
// output
//

func TestServerConfigFlags(t *testing.T) {
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

// slicesEqualIgnoreOrder compares two string slices, ignoring order
func slicesEqualIgnoreOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
