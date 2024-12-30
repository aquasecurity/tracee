package cobra

import (
	"fmt"
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
			name: "Test cache configuration (cli flags)",
			yamlContent: `
cache:
    - cache-type=mem
    - mem-cache-size=556
`,
			key: "cache",
			expectedFlags: []string{
				"cache-type=mem",
				"mem-cache-size=556",
			},
		},
		{
			name: "Test cache configuration (structured flags)",
			yamlContent: `
cache:
    type: mem
    size: 1024
`,
			key: "cache",
			expectedFlags: []string{
				"cache-type=mem",
				"mem-cache-size=1024",
			},
		},
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
			name: "Test cri configuration (cli flags)",
			yamlContent: `
cri:
    - test1:/var/run/test1.sock
    - test2:/var/run/test2.sock
`,
			key: "cri",
			expectedFlags: []string{
				"test1:/var/run/test1.sock",
				"test2:/var/run/test2.sock",
			},
		},
		{
			name: "Test cri configuration (structured flags)",
			// test1: /var/run/test1.sock
			// test2: /var/run/test2.sock
			yamlContent: `
cri:
    - runtime:
        name: test1
        socket: /var/run/test1.sock
    - runtime:
        name: test2
        socket: /var/run/test2.sock
`,
			key: "cri",
			expectedFlags: []string{
				"test1:/var/run/test1.sock",
				"test2:/var/run/test2.sock",
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
			name: "server flag check",
			yamlContent: `
server:
    http:
        address: localhost:8080
        metrics: false
        pprof: false
        healthz: true
        pyroscope: true
    grpc:
        address: unix:/var/run/tracee.sock`,
			key: "server",
			expectedFlags: []string{
				"grpc.address=unix:/var/run/tracee.sock",
				"http.address=localhost:8080",
				"http.healthz=true",
				"http.pyroscope=true",
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
// cache
//

func TestCacheConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   CacheConfig
		expected []string
	}{
		{
			name:     "empty config",
			config:   CacheConfig{},
			expected: []string{},
		},
		{
			name: "only type",
			config: CacheConfig{
				Type: "none",
			},
			expected: []string{
				"cache-type=none",
			},
		},
		{
			name: "both type and size",
			config: CacheConfig{
				Type: "mem",
				Size: 1024,
			},
			expected: []string{
				"cache-type=mem",
				"mem-cache-size=1024",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			flags := tt.config.flags()
			if !slicesEqualIgnoreOrder(flags, tt.expected) {
				t.Errorf("flags() = %v, want %v", flags, tt.expected)
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

func TestCRIConfigFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   CRIConfig
		expected []string
	}{
		{
			name: "empty config",
			config: CRIConfig{
				Name:   "",
				Socket: "",
			},
			expected: []string{},
		},
		{
			name: "valid config",
			config: CRIConfig{
				Name:   "testName",
				Socket: "/var/run/socket.sock",
			},
			expected: []string{
				"testName:/var/run/socket.sock",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.flags()
			if len(got) != len(tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
			if len(got) > 0 && got[0] != tt.expected[0] {
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
			name: "empty config",
			config: ServerConfig{
				Http: HttpConfig{},
				Grpc: GrpcConfig{},
			},
			expected: []string{},
		},
		{
			name: "grpc only",
			config: ServerConfig{
				Http: HttpConfig{},
				Grpc: GrpcConfig{
					Address: "unix:/var/run/tracee.sock",
				},
			},
			expected: []string{
				"grpc.address=unix:/var/run/tracee.sock",
			},
		},
		{
			name: "http only",
			config: ServerConfig{
				Http: HttpConfig{
					Address: "localhost:8080",
				},
				Grpc: GrpcConfig{},
			},
			expected: []string{
				"http.address=localhost:8080",
			},
		},
		{
			name: "http with options",
			config: ServerConfig{
				Http: HttpConfig{
					Address:   "localhost:8080",
					Metrics:   true,
					Pprof:     true,
					Healthz:   true,
					Pyroscope: true,
				},
				Grpc: GrpcConfig{},
			},
			expected: []string{
				"http.address=localhost:8080",
				"http.metrics=true",
				"http.pprof=true",
				"http.healthz=true",
				"http.pyroscope=true",
			},
		},
		{
			name: "both http and grpc",
			config: ServerConfig{
				Http: HttpConfig{
					Address: "localhost:8080",
				},
				Grpc: GrpcConfig{
					Address: "unix:/var/run/tracee.sock",
				},
			},
			expected: []string{
				"grpc.address=unix:/var/run/tracee.sock",
				"http.address=localhost:8080",
			},
		},
		{
			name: "both http and grpc with options",
			config: ServerConfig{
				Http: HttpConfig{
					Address:   "localhost:8080",
					Metrics:   true,
					Pprof:     true,
					Healthz:   true,
					Pyroscope: true,
				},
				Grpc: GrpcConfig{
					Address: "unix:/var/run/tracee.sock",
				},
			},
			expected: []string{
				"grpc.address=unix:/var/run/tracee.sock",
				"http.address=localhost:8080",
				"http.metrics=true",
				"http.pprof=true",
				"http.healthz=true",
				"http.pyroscope=true",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.flags()
			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			} else {
				fmt.Println(got)
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
