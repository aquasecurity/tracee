package cobra

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
			name: "Test log configuration (cli flags)",
			yamlContent: `
log:
    - debug
    - file:/var/log/test.log
    - aggregate:5s
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
			key: "log",
			expectedFlags: []string{
				"debug",
				"file:/var/log/test.log",
				"aggregate:5s",
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
log:
    level: debug
    file: /var/log/test.log
    aggregate:
        enabled: true
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
			key: "log",
			expectedFlags: []string{
				"level=debug",
				"file=/var/log/test.log",
				"aggregate.enabled=true",
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
			name: "Test output configuration (structured flags)",
			yamlContent: `
output:
    options:
        none: false
        stack-addresses: true
        exec-env: true
        exec-hash: dev-inode
        parse-arguments: true
        parse-arguments-fds: true
        sort-events: true
    table:
        files:
            - file1
    table-verbose:
        files:
            - stdout
    json:
        files:
            - /path/to/json1.out
    gotemplate:
        template: template1
        files:
            - file3
            - file4
    forward:
        - forward1:
            protocol: tcp
            user: user
            password: pass
            host: 127.0.0.1
            port: 24224
            tag: tracee1
        - forward2:
            protocol: udp
            user: user
            password: pass
            host: 127.0.0.1
            port: 24225
            tag: tracee2
    webhook:
        - webhook1:
            protocol: http
            host: localhost
            port: 8000
            timeout: 5s
            gotemplate: /path/to/template1
            content-type: application/json
        - webhook2:
            protocol: http
            host: localhost
            port: 9000
            timeout: 3s
            gotemplate: /path/to/template2
            content-type: application/ld+json
`,
			key: "output",
			expectedFlags: []string{
				"option:stack-addresses",
				"option:exec-env",
				"option:exec-hash=dev-inode",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
				"table:file1",
				"table-verbose:stdout",
				"json:/path/to/json1.out",
				"gotemplate=template1:file3,file4",
				"forward:tcp://user:pass@127.0.0.1:24224?tag=tracee1",
				"forward:udp://user:pass@127.0.0.1:24225?tag=tracee2",
				"webhook:http://localhost:8000?timeout=5s&gotemplate=/path/to/template1&contentType=application/json",
				"webhook:http://localhost:9000?timeout=3s&gotemplate=/path/to/template2&contentType=application/ld+json",
			},
		},
		{
			name: "Test buffers configuration (cli flags)",
			yamlContent: `
buffers:
    - kernel-events=2048
    - kernel-blob=512
    - control-plane-events=256
    - pipeline=4000
`,
			key: "buffers",
			expectedFlags: []string{
				"kernel-events=2048",
				"kernel-blob=512",
				"control-plane-events=256",
				"pipeline=4000",
			},
		},
		{
			name: "Test buffers configuration (structured flags)",
			yamlContent: `
buffers:
    kernel-events: 2048
    kernel-blob: 512
    control-plane-events: 256
    pipeline: 4000
`,
			key: "buffers",
			expectedFlags: []string{
				"kernel-events=2048",
				"kernel-blob=512",
				"control-plane-events=256",
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
			name: "Test enrich configuration (cli flags)",
			yamlContent: `
enrich:
    - container.enabled=true
    - container.cgroup.path=/host/sys/fs/cgroup
    - container.docker.socket=/var/run/docker.sock
    - container.containerd.socket=/var/run/containerd/containerd.sock
    - container.crio.socket=/var/run/crio/crio.sock
    - container.podman.socket=/var/run/podman/podman.sock
    - resolve-fd=true
    - exec-hash.enabled=true
    - exec-hash.mode=dev-inode
    - user-stack-trace=true
`,
			key: "enrich",
			expectedFlags: []string{
				"container.enabled=true",
				"container.cgroup.path=/host/sys/fs/cgroup",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd=true",
				"exec-hash.enabled=true",
				"exec-hash.mode=dev-inode",
				"user-stack-trace=true",
			},
		},
		{
			name: "Test enrich configuration (structured flags)",
			yamlContent: `
enrich:
    container-enabled: true
    container-cgroup-path: /host/sys/fs/cgroup
    container-docker-socket: /var/run/docker.sock
    container-containerd-socket: /var/run/containerd/containerd.sock
    container-crio-socket: /var/run/crio/crio.sock
    container-podman-socket: /var/run/podman/podman.sock
    resolve-fd: true
    exec-hash-enabled: true
    exec-hash-mode: dev-inode
    user-stack-trace: true
`,
			key: "enrich",
			expectedFlags: []string{
				"container.enabled=true",
				"container.cgroup.path=/host/sys/fs/cgroup",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd=true",
				"exec-hash.enabled=true",
				"exec-hash.mode=dev-inode",
				"user-stack-trace=true",
			},
		},
		{
			name: "Test general configuration (cli flags)",
			yamlContent: `
general:
    - workdir=/tmp/tracee
`,
			key: "general",
			expectedFlags: []string{
				"workdir=/tmp/tracee",
			},
		},
		{
			name: "Test general configuration (structured flags)",
			yamlContent: `
general:
    workdir: /opt/tracee
`,
			key: "general",
			expectedFlags: []string{
				"workdir=/opt/tracee",
			},
		},
		{
			name: "Test signatures configuration (cli flags)",
			yamlContent: `
signatures:
    - search-paths=/path/to/signatures
`,
			key: "signatures",
			expectedFlags: []string{
				"search-paths=/path/to/signatures",
			},
		},
		{
			name: "Test signatures configuration (structured flags)",
			yamlContent: `
signatures:
    search-paths:
        - /path/to/signatures
`,
			key: "signatures",
			expectedFlags: []string{
				"search-paths=/path/to/signatures",
			},
		},
		{
			name: "Test signatures configuration (cli flags - multiple paths)",
			yamlContent: `
signatures:
    - search-paths=/path1,/path2
`,
			key: "signatures",
			expectedFlags: []string{
				"search-paths=/path1,/path2",
			},
		},
		{
			name: "Test signatures configuration (structured flags - multiple paths)",
			yamlContent: `
signatures:
    search-paths:
        - /path/to/signatures1
        - /path/to/signatures2
        - /opt/tracee/signatures
`,
			key: "signatures",
			expectedFlags: []string{
				"search-paths=/path/to/signatures1,/path/to/signatures2,/opt/tracee/signatures",
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
				"level=debug",
			},
		},
		{
			name: "file only",
			config: LogConfig{
				File: "/var/log/test.log",
			},
			expected: []string{
				"file=/var/log/test.log",
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
				"aggregate.enabled=true",
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
				"aggregate.enabled=true",
				"aggregate.flush-interval=5s",
			},
		},
		{
			name: "filters with libbpf",
			config: LogConfig{
				Filters: LogFilterConfig{
					Include: LogFilterAttributes{
						LibBPF: true,
					},
				},
			},
			expected: []string{
				"filters.include.libbpf",
			},
		},
		{
			name: "filters with attributes",
			config: LogConfig{
				Filters: LogFilterConfig{
					Include: LogFilterAttributes{
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
				"filters.include.msg=msg1",
				"filters.include.msg=msg2",
				"filters.include.pkg=pkg1",
				"filters.include.file=file1",
				"filters.include.file=file2",
				"filters.include.level=lvl1",
				"filters.include.regex=^test.*",
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
					Include: LogFilterAttributes{
						Msg:    []string{"msg1"},
						Pkg:    []string{"pkg1", "pkg2"},
						File:   []string{"file1"},
						Level:  []string{"lvl1", "lvl2"},
						Regex:  []string{"^regex.*"},
						LibBPF: true,
					},
					Exclude: LogFilterAttributes{
						Msg:   []string{"msg1"},
						Pkg:   []string{"pkg1"},
						File:  []string{"file1", "file2"},
						Level: []string{"lvl1"},
						Regex: []string{"^regex.*"},
					},
				},
			},
			expected: []string{
				"level=debug",
				"file=/var/log/test.log",
				"aggregate.flush-interval=10s",
				"aggregate.enabled=true",
				"filters.include.libbpf",
				"filters.include.msg=msg1",
				"filters.include.pkg=pkg1",
				"filters.include.pkg=pkg2",
				"filters.include.file=file1",
				"filters.include.level=lvl1",
				"filters.include.level=lvl2",
				"filters.include.regex=^regex.*",
				"filters.exclude.msg=msg1",
				"filters.exclude.pkg=pkg1",
				"filters.exclude.file=file1",
				"filters.exclude.file=file2",
				"filters.exclude.level=lvl1",
				"filters.exclude.regex=^regex.*",
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

func TestOutputConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   OutputConfig
		expected []string
	}{
		{
			name:     "empty config",
			config:   OutputConfig{},
			expected: []string{},
		},
		{
			name: "options set",
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
			expected: []string{
				"none",
				"option:stack-addresses",
				"option:exec-env",
				"option:exec-hash=dev-inode",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
		},
		{
			name: "formats set",
			config: OutputConfig{
				Table: OutputFormatConfig{
					Files: []string{"file1"},
				},
				JSON: OutputFormatConfig{
					Files: []string{"file2"},
				},
			},
			expected: []string{
				"table:file1",
				"json:file2",
			},
		},
		{
			name: "gotemplate set",
			config: OutputConfig{
				GoTemplate: OutputGoTemplateConfig{
					Template: "template1",
					Files:    []string{"file3", "file4"},
				},
			},
			expected: []string{
				"gotemplate=template1:file3,file4",
			},
		},
		{
			name: "test forward with tag",
			config: OutputConfig{
				Forwards: map[string]OutputForwardConfig{
					"example1": {
						Protocol: "tcp",
						User:     "",
						Password: "",
						Host:     "example.com",
						Port:     8080,
						Tag:      "sample",
					},
				},
			},
			expected: []string{
				"forward:tcp://example.com:8080?tag=sample",
			},
		},
		{
			name: "test forward with user and password",
			config: OutputConfig{
				Forwards: map[string]OutputForwardConfig{
					"example2": {
						Protocol: "tcp",
						User:     "user123",
						Password: "pass123",
						Host:     "secure.com",
						Port:     443,
						Tag:      "",
					},
				},
			},
			expected: []string{
				"forward:tcp://user123:pass123@secure.com:443",
			},
		},
		{
			name: "test webhook with all fields",
			config: OutputConfig{
				Webhooks: map[string]OutputWebhookConfig{
					"example3": {
						Protocol:    "http",
						Host:        "webhook.com",
						Port:        9090,
						Timeout:     "5s",
						GoTemplate:  "/path/to/template1",
						ContentType: "application/json",
					},
				},
			},
			expected: []string{
				"webhook:http://webhook.com:9090?timeout=5s&gotemplate=/path/to/template1&contentType=application/json",
			},
		},
		{
			name: "test combined forward and webhook",
			config: OutputConfig{
				Forwards: map[string]OutputForwardConfig{
					"example4": {
						Protocol: "http",
						User:     "",
						Password: "",
						Host:     "combined.com",
						Port:     8000,
						Tag:      "taggy",
					},
				},
				Webhooks: map[string]OutputWebhookConfig{
					"example5": {
						Protocol: "http",
						Host:     "hooky.com",
						Port:     8088,
						Timeout:  "10s",
					},
				},
			},
			expected: []string{
				"forward:http://combined.com:8000?tag=taggy",
				"webhook:http://hooky.com:8088?timeout=10s",
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

//
// enrich
//

func TestEnrichConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   EnrichConfig
		expected []string
	}{
		{
			name: "empty config",
			config: EnrichConfig{
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
			expected: []string{},
		},
		{
			name: "container enabled only",
			config: EnrichConfig{
				ContainerEnabled: true,
			},
			expected: []string{
				"container.enabled=true",
			},
		},
		{
			name: "container sockets only",
			config: EnrichConfig{
				ContainerDockerSocket:     "/var/run/docker.sock",
				ContainerContainerdSocket: "/var/run/containerd/containerd.sock",
				ContainerCrioSocket:       "/var/run/crio/crio.sock",
				ContainerPodmanSocket:     "/var/run/podman/podman.sock",
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
			config: EnrichConfig{
				ContainerCgroupPath: "/host/sys/fs/cgroup",
			},
			expected: []string{
				"container.cgroup.path=/host/sys/fs/cgroup",
			},
		},
		{
			name: "resolve-fd enabled",
			config: EnrichConfig{
				ResolveFd: true,
			},
			expected: []string{
				"resolve-fd=true",
			},
		},
		{
			name: "exec-hash enabled",
			config: EnrichConfig{
				ExecHashEnabled: true,
			},
			expected: []string{
				"exec-hash.enabled=true",
			},
		},
		{
			name: "exec-hash mode",
			config: EnrichConfig{
				ExecHashMode: "dev-inode",
			},
			expected: []string{
				"exec-hash.mode=dev-inode",
			},
		},
		{
			name: "user-stack-trace enabled",
			config: EnrichConfig{
				UserStackTrace: true,
			},
			expected: []string{
				"user-stack-trace=true",
			},
		},
		{
			name: "all options enabled",
			config: EnrichConfig{
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
			expected: []string{
				"container.enabled=true",
				"container.cgroup.path=/host/sys/fs/cgroup",
				"container.docker.socket=/var/run/docker.sock",
				"container.containerd.socket=/var/run/containerd/containerd.sock",
				"container.crio.socket=/var/run/crio/crio.sock",
				"container.podman.socket=/var/run/podman/podman.sock",
				"resolve-fd=true",
				"exec-hash.enabled=true",
				"exec-hash.mode=dev-inode",
				"user-stack-trace=true",
			},
		},
		{
			name: "partial container configuration",
			config: EnrichConfig{
				ContainerEnabled:      true,
				ContainerDockerSocket: "/var/run/docker.sock",
				ResolveFd:             true,
			},
			expected: []string{
				"container.enabled=true",
				"container.docker.socket=/var/run/docker.sock",
				"resolve-fd=true",
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
// signatures
//

func TestSignaturesConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   SignaturesConfig
		expected []string
	}{
		{
			config: SignaturesConfig{
				SearchPaths: []string{},
			},
			expected: []string{},
		},
		{
			name: "single search path",
			config: SignaturesConfig{
				SearchPaths: []string{"/path/to/signatures"},
			},
			expected: []string{
				"search-paths=/path/to/signatures",
			},
		},
		{
			name: "multiple search paths",
			config: SignaturesConfig{
				SearchPaths: []string{
					"/path/to/signatures1,/path/to/signatures2,/opt/tracee/signatures",
				},
			},
			expected: []string{
				"search-paths=/path/to/signatures1,/path/to/signatures2,/opt/tracee/signatures",
			},
		},
		{
			name: "relative paths",
			config: SignaturesConfig{
				SearchPaths: []string{
					"./signatures",
					"../other/signatures",
				},
			},
			expected: []string{
				"search-paths=./signatures,../other/signatures",
			},
		},
		{
			name: "mixed absolute and relative paths",
			config: SignaturesConfig{
				SearchPaths: []string{
					"/usr/local/signatures",
					"./local/signatures",
					"/opt/tracee/signatures",
				},
			},
			expected: []string{
				"search-paths=/usr/local/signatures,./local/signatures,/opt/tracee/signatures",
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
// general
//

func TestGeneralConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   GeneralConfig
		expected []string
	}{
		{
			name: "empty config",
			config: GeneralConfig{
				Workdir: "",
			},
			expected: []string{
				"workdir=",
			},
		},
		{
			name: "default workdir",
			config: GeneralConfig{
				Workdir: "/tmp/tracee",
			},
			expected: []string{
				"workdir=/tmp/tracee",
			},
		},
		{
			name: "custom workdir",
			config: GeneralConfig{
				Workdir: "/opt/tracee",
			},
			expected: []string{
				"workdir=/opt/tracee",
			},
		},
		{
			name: "workdir with custom path",
			config: GeneralConfig{
				Workdir: "/var/lib/tracee",
			},
			expected: []string{
				"workdir=/var/lib/tracee",
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
