package cobra

import (
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/pkg/config"
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
			name: "Test proctree configuration (cli flags)",
			yamlContent: `
proctree:
    - source=events
    - process-cache=8192
    - thread-cache=4096
`,
			key: "proctree",
			expectedFlags: []string{
				"source=events",
				"process-cache=8192",
				"thread-cache=4096",
			},
		},
		{
			name: "Test proctree configuration (structured flags)",
			yamlContent: `
proctree:
    source: events
    cache:
        process: 8192
        thread: 4096
`,
			key: "proctree",
			expectedFlags: []string{
				"source=events",
				"process-cache=8192",
				"thread-cache=4096",
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
			name: "Test containers socket configuration",
			yamlContent: `
containers:
  enrich: true
  cgroupfs:
    path: /host/sys/fs/cgroup
    force: true
  sockets:
    - runtime: docker
      socket: /var/run/test2.sock
    - runtime: crio
      socket: /var/run/test1.sock
`,
			key: "containers",
			expectedFlags: []string{
				"sockets.docker=/var/run/test2.sock",
				"sockets.crio=/var/run/test1.sock",
				"cgroupfs.path=/host/sys/fs/cgroup",
				"cgroupfs.force=true",
				"enrich=true",
			},
		},
		{
			name: "Test log configuration (cli flags)",
			yamlContent: `
log:
    - debug
    - file:/var/log/test.log
    - aggregate:5s
    - filter:libbpf
    - filter:msg=msg1
    - filter:pkg=pkg1
    - filter:pkg=pkg2
    - filter:file=file1
    - filter:lvl=info
    - filter:regex=^regex.*
    - filter-out:msg=msg1
    - filter-out:pkg=pkg1
    - filter-out:file=file1
    - filter-out:file=file2
    - filter-out:lvl=info
    - filter-out:regex=^regex.*
`,
			key: "log",
			expectedFlags: []string{
				"debug",
				"file:/var/log/test.log",
				"aggregate:5s",
				"filter:libbpf",
				"filter:msg=msg1",
				"filter:pkg=pkg1",
				"filter:pkg=pkg2",
				"filter:file=file1",
				"filter:lvl=info",
				"filter:regex=^regex.*",
				"filter-out:msg=msg1",
				"filter-out:pkg=pkg1",
				"filter-out:file=file1",
				"filter-out:file=file2",
				"filter-out:lvl=info",
				"filter-out:regex=^regex.*",
			},
		},
		{
			name: "Test log configuration (structured flags)",
			yamlContent: `
log:
    level: debug
    file: /var/log/test.log
    aggregate:
        enabled: true
        flush-interval: 5s
    filters:
        libbpf: true
        in:
            msg:
                - msg1
            pkg:
                - pkg1
                - pkg2
            file:
                - file1
            lvl:
                - info
            regex:
                - ^regex.*
        out:
            msg:
                - msg1
            pkg:
                - pkg1
            file:
                - file1
                - file2
            lvl:
                - info
            regex:
                - ^regex.*
`,
			key: "log",
			expectedFlags: []string{
				"debug",
				"file:/var/log/test.log",
				"aggregate:5s",
				"filter:libbpf",
				"filter:msg=msg1",
				"filter:pkg=pkg1",
				"filter:pkg=pkg2",
				"filter:file=file1",
				"filter:lvl=info",
				"filter:regex=^regex.*",
				"filter-out:msg=msg1",
				"filter-out:pkg=pkg1",
				"filter-out:file=file1",
				"filter-out:file=file2",
				"filter-out:lvl=info",
				"filter-out:regex=^regex.*",
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
			name: "server flag check",
			yamlContent: `
server:
    http-address: localhost:8080
    grpc-address: unix:/var/run/tracee.sock
    metrics: false
    pprof: false
    healthz: true
    pyroscope: true`,
			key: "server",
			expectedFlags: []string{
				"grpc-address=unix:/var/run/tracee.sock",
				"http-address=localhost:8080",
				"healthz",
				"pyroscope",
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
// proctree
//

func TestProcTreeConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   ProcTreeConfig
		expected []string
	}{
		{
			name: "empty config",
			config: ProcTreeConfig{
				Source: "",
				Cache:  ProcTreeCacheConfig{},
			},
			expected: []string{},
		},
		{
			name: "only source set",
			config: ProcTreeConfig{
				Source: "events",
				Cache:  ProcTreeCacheConfig{},
			},
			expected: []string{
				"source=events",
			},
		},
		{
			name: "only process cache set",
			config: ProcTreeConfig{
				Source: "",
				Cache: ProcTreeCacheConfig{
					Process: 8192,
				},
			},
			expected: []string{
				"process-cache=8192",
			},
		},
		{
			name: "only thread cache set",
			config: ProcTreeConfig{
				Source: "",
				Cache: ProcTreeCacheConfig{
					Thread: 4096,
				},
			},
			expected: []string{
				"thread-cache=4096",
			},
		},
		{
			name: "both cache values set",
			config: ProcTreeConfig{
				Source: "",
				Cache: ProcTreeCacheConfig{
					Process: 8192,
					Thread:  4096,
				},
			},
			expected: []string{
				"process-cache=8192",
				"thread-cache=4096",
			},
		},
		{
			name: "all fields set",
			config: ProcTreeConfig{
				Source: "events",
				Cache: ProcTreeCacheConfig{
					Process: 8192,
					Thread:  4096,
				},
			},
			expected: []string{
				"source=events",
				"process-cache=8192",
				"thread-cache=4096",
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
// cri
//

func TestContainerConfigFlag(t *testing.T) {
	t.Parallel()

	truePtr := true
	falsePtr := false

	tests := []struct {
		name     string
		config   ContainerConfig
		expected []string
	}{
		{
			name: "empty config",
			expected: []string{
				"enrich=true",
			},
		},
		{
			name: "valid config (socket)",
			config: ContainerConfig{
				Sockets: []SocketConfig{
					{
						Runtime: "testName",
						Socket:  "/var/run/socket.sock",
					},
				},
			},
			expected: []string{
				"enrich=true",
				"sockets.testName=/var/run/socket.sock",
			},
		},
		{
			name: "valid config (cgroupfs)",
			config: ContainerConfig{
				Cgroupfs: CgroupfsConfig{
					Path:  "/host/sys/fs/cgroup",
					Force: false,
				},
			},
			expected: []string{
				"enrich=true",
				"cgroupfs.path=/host/sys/fs/cgroup",
			},
		},
		{
			name: "valid config (enrich=true)",
			config: ContainerConfig{
				Enrich: &truePtr,
			},
			expected: []string{
				"enrich=true",
			},
		},
		{
			name: "valid config (enrich=false)",
			config: ContainerConfig{
				Enrich: &falsePtr,
			},
			expected: []string{
				"enrich=false",
			},
		},
		{
			name: "valid config (combined)",
			config: ContainerConfig{
				Sockets: []SocketConfig{
					{
						Runtime: "docker",
						Socket:  "/var/run/docker.sock",
					},
					{
						Runtime: "crio",
						Socket:  "/var/run/crio.sock",
					},
				},
				Cgroupfs: CgroupfsConfig{
					Path:  "/host/sys/fs/cgroup",
					Force: true,
				},
				Enrich: &truePtr,
			},
			expected: []string{
				"sockets.docker=/var/run/docker.sock",
				"sockets.crio=/var/run/crio.sock",
				"cgroupfs.path=/host/sys/fs/cgroup",
				"cgroupfs.force=true",
				"enrich=true",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.flags()
			assert.Equal(t, len(tt.expected), len(got), "Expected %d flags, got %d flags", len(tt.expected), len(got))
			assert.ElementsMatch(t, tt.expected, got, "Expected %v, got %v", tt.expected, got)
		})
	}
}

//
// log
//

func TestLogConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   LogConfig
		expected []string
	}{
		{
			name: "empty config",
			config: LogConfig{
				Level: "",
				File:  "",
			},
			expected: []string{},
		},
		{
			name: "level only",
			config: LogConfig{
				Level: "debug",
			},
			expected: []string{
				"debug",
			},
		},
		{
			name: "file only",
			config: LogConfig{
				File: "/var/log/test.log",
			},
			expected: []string{
				"file:/var/log/test.log",
			},
		},
		{
			name: "aggregate only",
			config: LogConfig{
				Aggregate: LogAggregateConfig{
					Enabled:       true,
					FlushInterval: "",
				},
			},
			expected: []string{
				"aggregate",
			},
		},
		{
			name: "aggregate with interval",
			config: LogConfig{
				Aggregate: LogAggregateConfig{
					Enabled:       true,
					FlushInterval: "5s",
				},
			},
			expected: []string{
				"aggregate:5s",
			},
		},
		{
			name: "filters with libbpf",
			config: LogConfig{
				Filters: LogFilterConfig{
					LibBPF: true,
				},
			},
			expected: []string{
				"filter:libbpf",
			},
		},
		{
			name: "filters with attributes",
			config: LogConfig{
				Filters: LogFilterConfig{
					In: LogFilterAttributes{
						Msg: []string{
							"msg1",
							"msg2",
						},
						Pkg: []string{
							"pkg1",
						},
						File: []string{
							"file1",
							"file2",
						},
						Level: []string{
							"lvl1",
						},
						Regex: []string{
							"^test.*",
						},
					},
				},
			},
			expected: []string{
				"filter:msg=msg1",
				"filter:msg=msg2",
				"filter:pkg=pkg1",
				"filter:file=file1",
				"filter:file=file2",
				"filter:lvl=lvl1",
				"filter:regex=^test.*",
			},
		},
		{
			name: "all flags",
			config: LogConfig{
				Level: "debug",
				File:  "/var/log/test.log",
				Aggregate: LogAggregateConfig{
					Enabled:       true,
					FlushInterval: "10s",
				},
				Filters: LogFilterConfig{
					LibBPF: true,
					In: LogFilterAttributes{
						Msg:   []string{"msg1"},
						Pkg:   []string{"pkg1", "pkg2"},
						File:  []string{"file1"},
						Level: []string{"lvl1", "lvl2"},
						Regex: []string{"^regex.*"},
					},
					Out: LogFilterAttributes{
						Msg:   []string{"msg1"},
						Pkg:   []string{"pkg1"},
						File:  []string{"file1", "file2"},
						Level: []string{"lvl1"},
						Regex: []string{"^regex.*"},
					},
				},
			},
			expected: []string{
				"debug",
				"file:/var/log/test.log",
				"aggregate:10s",
				"filter:libbpf",
				"filter:msg=msg1",
				"filter:pkg=pkg1",
				"filter:pkg=pkg2",
				"filter:file=file1",
				"filter:lvl=lvl1",
				"filter:lvl=lvl2",
				"filter:regex=^regex.*",
				"filter-out:msg=msg1",
				"filter-out:pkg=pkg1",
				"filter-out:file=file1",
				"filter-out:file=file2",
				"filter-out:lvl=lvl1",
				"filter-out:regex=^regex.*",
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

func TestOutputConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      OutputConfig
		expected    config.OutputConfig
		shouldError bool
	}{
		{
			name:   "empty config",
			config: OutputConfig{},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "default-stream",
						Destinations: []config.Destination{
							{
								Name:          "default-destination",
								Type:          "file",
								Format:        "table",
								Path:          "stdout",
								File:          os.Stdout,
								ContainerMode: config.ContainerModeEnriched,
							},
						},
					},
				},
			},
		},
		{
			name: "all options set",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None:              true,
					StackAddresses:    true,
					ExecEnv:           true,
					ExecHash:          "dev-inode",
					ParseArguments:    true,
					ParseArgumentsFDs: true,
					SortEvents:        true,
				},
			},
			expected: config.OutputConfig{
				StackAddresses:    true,
				ExecEnv:           true,
				CalcHashes:        digest.CalcHashesDevInode,
				ParseArguments:    true,
				ParseArgumentsFDs: true,
				EventsSorting:     true,
				Streams:           []config.Stream{},
			},
		},
		{
			name: "options set no sorting",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None:              true,
					StackAddresses:    true,
					ExecEnv:           true,
					ExecHash:          "dev-inode",
					ParseArguments:    true,
					ParseArgumentsFDs: true,
				},
			},
			expected: config.OutputConfig{
				StackAddresses:    true,
				ExecEnv:           true,
				CalcHashes:        digest.CalcHashesDevInode,
				ParseArguments:    true,
				ParseArgumentsFDs: true,
			},
		},
		{
			name: "options set no sorting no argument",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None:           true,
					StackAddresses: true,
					ExecEnv:        true,
					ExecHash:       "dev-inode",
				},
			},
			expected: config.OutputConfig{
				StackAddresses: true,
				ExecEnv:        true,
				CalcHashes:     digest.CalcHashesDevInode,
			},
		},
		{
			name: "options set no sorting no argument no hash",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None:           true,
					StackAddresses: true,
					ExecEnv:        true,
				},
			},
			expected: config.OutputConfig{
				StackAddresses: true,
				ExecEnv:        true,
			},
		},
		{
			name: "options set no sorting no argument no hash no env",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None:           true,
					StackAddresses: true,
				},
			},
			expected: config.OutputConfig{
				StackAddresses: true,
			},
		},
		{
			name: "options set no sorting no argument no hash no env no stack",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None: true,
				},
			},
			expected: config.OutputConfig{},
		},
		{
			name: "formats set",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "table",
						Type:   "file",
						Format: "table",
						Path:   path.Join(t.TempDir(), "file-1"),
					},
					{
						Name:   "json",
						Type:   "file",
						Format: "json",
						Path:   path.Join(t.TempDir(), "file-2"),
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "table-stream",
						Destinations: []config.Destination{
							{
								Name:   "table",
								Type:   "file",
								Format: "table",
								Path:   path.Join(t.TempDir(), "file-1"),
							},
						},
					},
					{
						Name: "json-stream",
						Destinations: []config.Destination{
							{
								Name:   "json",
								Type:   "file",
								Format: "table",
								Path:   path.Join(t.TempDir(), "file-1"),
							},
						},
					},
				},
			},
		},
		{
			name: "gotemplate set",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "template",
						Type:   "file",
						Format: "gotemplate=template1",
						Path:   path.Join(t.TempDir(), "file-1"),
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "template-stream",
						Destinations: []config.Destination{
							{
								Name:   "template",
								Type:   "file",
								Format: "gotemplate=template1",
								Path:   path.Join(t.TempDir(), "file-1"),
							},
						},
					},
				},
			},
		},
		{
			name: "test forward with tag",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "forward",
						Type:   "forward",
						Format: "json",
						Url:    "tcp://example.com:8080?tag=sample",
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "forward-stream",
						Destinations: []config.Destination{
							{
								Name:   "forward",
								Type:   "forward",
								Format: "json",
								Url:    "tcp://example.com:8080?tag=sample",
							},
						},
					},
				},
			},
		},
		{
			name: "test forward with template",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "forward",
						Type:   "forward",
						Format: "gotemplate=template1",
						Url:    "tcp://example.com:8080",
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "forward-stream",
						Destinations: []config.Destination{
							{
								Name:   "forward",
								Type:   "forward",
								Format: "gotemplate=template1",
								Url:    "tcp://example.com:8080",
							},
						},
					},
				},
			},
		},
		{
			name: "test webhook with all fields",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "webhook",
						Type:   "webhook",
						Format: "json",
						Url:    "http://webhook.com:9090?timeout=5s",
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "webhook-stream",
						Destinations: []config.Destination{
							{
								Name:   "webhook",
								Type:   "webhook",
								Format: "gotemplate=template1",
								Url:    "http://webhook.com:9090?timeout=5s",
							},
						},
					},
				},
			},
		},
		{
			name: "test combined forward and webhook",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "forward",
						Type:   "forward",
						Format: "json",
						Url:    "tcp://example.com:8080?tag=sample",
					},
					{
						Name:   "webhook",
						Type:   "webhook",
						Format: "json",
						Url:    "http://webhook.com:9090?timeout=5s",
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "forward-stream",
						Destinations: []config.Destination{
							{
								Name:   "forward",
								Type:   "forward",
								Format: "json",
								Url:    "tcp://example.com:8080?tag=sample",
							},
						},
					},
					{
						Name: "webhook-stream",
						Destinations: []config.Destination{
							{
								Name:   "webhook",
								Type:   "webhook",
								Format: "gotemplate=template1",
								Url:    "http://webhook.com:9090?timeout=5s",
							},
						},
					},
				},
			},
		},
		{
			name: "single stream with a single file destination",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "destination-1",
						Type:   "file",
						Format: "json",
					},
				},
				Streams: []StreamConfig{
					{
						Name:         "stream-forward-1",
						Destinations: []string{"destination-1"},
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "stream-forward-1",
						Destinations: []config.Destination{
							{
								Name:   "destination-1",
								Type:   "file",
								Format: "json",
							},
						},
					},
				},
			},
		},
		{
			name: "single stream with multiple destinations",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "destination-1",
						Type:   "file",
						Format: "json",
					},
					{
						Name:   "destination-2",
						Type:   "file",
						Format: "json",
						Path:   path.Join(t.TempDir(), "file-destination-2"),
					},
				},
				Streams: []StreamConfig{
					{
						Name:         "stream-forward-1",
						Destinations: []string{"destination-1", "destination-2"},
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "stream-forward-1",
						Destinations: []config.Destination{
							{
								Name:   "destination-1",
								Type:   "file",
								Format: "json",
								Path:   "stdout",
							},
							{
								Name:   "destination-2",
								Type:   "file",
								Format: "json",
								Path:   path.Join(t.TempDir(), "file-destination-2"),
							},
						},
					},
				},
			},
		},
		{
			name: "synthetic stream for unused destination",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "destination-1",
						Type:   "file",
						Format: "json",
					},
					{
						Name:   "destination-2",
						Type:   "file",
						Format: "json",
						Path:   path.Join(t.TempDir(), "file-destination-2"),
					},
				},
				Streams: []StreamConfig{
					{
						Name:         "stream-forward-1",
						Destinations: []string{"destination-1"},
					},
				},
			},
			expected: config.OutputConfig{
				Streams: []config.Stream{
					{
						Name: "stream-forward-1",
						Destinations: []config.Destination{
							{
								Name:   "destination-1",
								Type:   "file",
								Format: "json",
								Path:   "stdout",
							},
						},
					},
					{
						Name: "destination-2-stream",
						Destinations: []config.Destination{
							{
								Name:   "destination-2",
								Type:   "file",
								Format: "json",
								Path:   path.Join(t.TempDir(), "file-destination-2"),
							},
						},
					},
				},
			},
		},
		{
			name: "used destination not defined",
			config: OutputConfig{
				Streams: []StreamConfig{
					{
						Name:         "stream-forward-1",
						Destinations: []string{"not-existing-destination"},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "same destination reused two times",
			config: OutputConfig{
				Destinations: []DestinationsConfig{
					{
						Name:   "forward",
						Type:   "forward",
						Format: "json",
						Url:    "tcp://example.com:8080?tag=sample",
					},
				},
				Streams: []StreamConfig{
					{
						Name:         "stream-forward-1",
						Destinations: []string{"forward"},
					},
					{
						Name:         "stream-forward-2",
						Destinations: []string{"forward"},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "option.none true",
			config: OutputConfig{
				Options: OutputOptsConfig{
					None: true,
				},
			},
			expected:    config.OutputConfig{},
			shouldError: false,
		},
	}

	streamSorter := func(array []config.Stream) func(int, int) bool {
		return func(i, j int) bool {
			return strings.Compare(array[i].Name, array[j].Name) > 0
		}
	}

	destinationSorter := func(array []config.Destination) func(int, int) bool {
		return func(i, j int) bool {
			return strings.Compare(array[i].Name, array[j].Name) > 0
		}
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := prepareTraceeConfig(tt.config, config.ContainerModeEnriched)
			if tt.shouldError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, got.CalcHashes, tt.expected.CalcHashes)
			assert.Equal(t, got.EventsSorting, tt.expected.EventsSorting)
			assert.Equal(t, got.ExecEnv, tt.expected.ExecEnv)
			assert.Equal(t, got.ParseArguments, tt.expected.ParseArguments)
			assert.Equal(t, got.ParseArgumentsFDs, tt.expected.ParseArgumentsFDs)
			assert.Equal(t, got.StackAddresses, tt.expected.StackAddresses)
			assert.Equal(t, len(got.Streams), len(tt.expected.Streams))

			sort.Slice(got.Streams, streamSorter(got.Streams))
			sort.Slice(tt.expected.Streams, streamSorter(tt.expected.Streams))

			for sIdx, stream := range got.Streams {
				assert.Equal(t, stream.Name, tt.expected.Streams[sIdx].Name)

				slicesEqualIgnoreOrder(stream.Filters.Events, tt.expected.Streams[sIdx].Filters.Events)
				slicesEqualIgnoreOrder(stream.Filters.Policies, tt.expected.Streams[sIdx].Filters.Policies)

				assert.Equal(t, stream.Buffer.Size, tt.expected.Streams[sIdx].Buffer.Size)
				assert.Equal(t, stream.Buffer.Mode, tt.expected.Streams[sIdx].Buffer.Mode)

				sort.Slice(stream.Destinations, destinationSorter(stream.Destinations))
				sort.Slice(tt.expected.Streams[sIdx].Destinations, destinationSorter(tt.expected.Streams[sIdx].Destinations))

				for dIdx, destination := range stream.Destinations {
					assert.Equal(t, destination.Name, stream.Destinations[dIdx].Name)
					assert.Equal(t, destination.Path, stream.Destinations[dIdx].Path)
					assert.Equal(t, destination.Url, stream.Destinations[dIdx].Url)
					assert.Equal(t, destination.Type, stream.Destinations[dIdx].Type)
					assert.Equal(t, destination.Format, stream.Destinations[dIdx].Format)

					if destination.Path != "stdout" && destination.Path != "" {
						assert.NotNil(t, destination.File)
					}
				}
			}
		})
	}
}

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

func destinationsEqualIgnoreOrder(a, b []config.Destination) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
