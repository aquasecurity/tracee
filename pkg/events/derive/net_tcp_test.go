package derive

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_NetTCPConnect_Derive(t *testing.T) {
	tests := []struct {
		name           string
		inputEvent     trace.Event
		expectedEvents []trace.Event
		expectedErrors []error
	}{
		{
			name: "TCP IPv4 connection",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(3)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)}, // SOCK_STREAM
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_addr":  "192.168.1.100",
							"sin_port":  "443",
						},
					},
				},
			},
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.NetTCPConnect),
					EventName: "net_tcp_connect",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dst", Type: "string"}, Value: "192.168.1.100"},
						{ArgMeta: trace.ArgMeta{Name: "dst_port", Type: "int32"}, Value: 443},
						{ArgMeta: trace.ArgMeta{Name: "dst_dns", Type: "[]string"}, Value: []string{}},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "TCP IPv6 connection",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(4)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)}, // SOCK_STREAM
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET6",
							"sin6_addr": "2001:db8::1",
							"sin6_port": "80",
						},
					},
				},
			},
			expectedEvents: []trace.Event{
				{
					EventID:   int(events.NetTCPConnect),
					EventName: "net_tcp_connect",
					Args: []trace.Argument{
						{ArgMeta: trace.ArgMeta{Name: "dst", Type: "string"}, Value: "2001:db8::1"},
						{ArgMeta: trace.ArgMeta{Name: "dst_port", Type: "int32"}, Value: 80},
						{ArgMeta: trace.ArgMeta{Name: "dst_dns", Type: "[]string"}, Value: []string{}},
					},
				},
			},
			expectedErrors: nil,
		},
		{
			name: "non-TCP socket (UDP) - should not derive",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(5)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(2)}, // SOCK_DGRAM
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_addr":  "8.8.8.8",
							"sin_port":  "53",
						},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: nil,
		},
		{
			name: "Unix domain socket - should not derive",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(6)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)}, // SOCK_STREAM
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_UNIX",
							"sun_path":  "/var/run/docker.sock",
						},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: nil,
		},
		{
			name: "missing type argument",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(7)},
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_addr":  "10.0.0.1",
							"sin_port":  "22",
						},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: []error{},
		},
		{
			name: "missing remote_addr argument",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(8)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)},
				},
			},
			expectedEvents: nil,
			expectedErrors: []error{},
		},
		{
			name: "malformed remote_addr - missing sa_family",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(9)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)},
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sin_addr": "192.168.1.1",
							"sin_port": "8080",
						},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: []error{},
		},
		{
			name: "malformed IPv4 address - missing sin_addr",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(10)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)},
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_port":  "9090",
						},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: []error{},
		},
		{
			name: "malformed port - non-numeric",
			inputEvent: trace.Event{
				EventID:   int(events.SecuritySocketConnect),
				EventName: "security_socket_connect",
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "sockfd", Type: "int32"}, Value: int32(11)},
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)},
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_addr":  "172.16.0.1",
							"sin_port":  "not-a-number",
						},
					},
				},
			},
			expectedEvents: nil,
			expectedErrors: []error{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Test without DNS cache (nil cache)
			deriveFunction := NetTCPConnect(nil)
			events, errs := deriveFunction(&tt.inputEvent)

			if len(tt.expectedErrors) > 0 {
				assert.NotEmpty(t, errs)
			} else if tt.expectedEvents == nil {
				// Should not derive - no events and possibly no errors
				assert.Empty(t, events)
			} else {
				assert.Empty(t, errs)
			}

			if tt.expectedEvents != nil {
				require.Len(t, events, len(tt.expectedEvents))
				for i, expectedEvent := range tt.expectedEvents {
					actualEvent := events[i]
					assert.Equal(t, expectedEvent.EventID, actualEvent.EventID)
					assert.Equal(t, expectedEvent.EventName, actualEvent.EventName)
					require.Len(t, actualEvent.Args, len(expectedEvent.Args))
					for j, expectedArg := range expectedEvent.Args {
						assert.Equal(t, expectedArg.ArgMeta.Name, actualEvent.Args[j].ArgMeta.Name)
						assert.Equal(t, expectedArg.Value, actualEvent.Args[j].Value, "Arg %s mismatch", expectedArg.ArgMeta.Name)
					}
				}
			} else {
				assert.Empty(t, events)
			}
		})
	}
}

func Test_NetTCPConnect_PickIpAndPort(t *testing.T) {
	tests := []struct {
		name         string
		event        trace.Event
		fieldName    string
		expectedIP   string
		expectedPort int
		shouldError  bool
	}{
		{
			name: "IPv4 address extraction",
			event: trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)}, // SOCK_STREAM
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_addr":  "192.0.2.1",
							"sin_port":  "8080",
						},
					},
				},
			},
			fieldName:    "remote_addr",
			expectedIP:   "192.0.2.1",
			expectedPort: 8080,
			shouldError:  false,
		},
		{
			name: "IPv6 address extraction",
			event: trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)},
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET6",
							"sin6_addr": "fe80::1",
							"sin6_port": "443",
						},
					},
				},
			},
			fieldName:    "remote_addr",
			expectedIP:   "fe80::1",
			expectedPort: 443,
			shouldError:  false,
		},
		{
			name: "non-TCP socket returns empty",
			event: trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(2)}, // SOCK_DGRAM
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_INET",
							"sin_addr":  "10.0.0.1",
							"sin_port":  "53",
						},
					},
				},
			},
			fieldName:    "remote_addr",
			expectedIP:   "",
			expectedPort: 0,
			shouldError:  false,
		},
		{
			name: "AF_UNIX socket returns empty",
			event: trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "type", Type: "int32"}, Value: int32(1)},
					{
						ArgMeta: trace.ArgMeta{Name: "remote_addr", Type: "SockAddr"},
						Value: map[string]string{
							"sa_family": "AF_UNIX",
							"sun_path":  "/tmp/socket",
						},
					},
				},
			},
			fieldName:    "remote_addr",
			expectedIP:   "",
			expectedPort: 0,
			shouldError:  false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := pickIpAndPort(&tt.event, tt.fieldName)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				if tt.expectedIP == "" {
					// Function should not error but return empty values
					assert.NoError(t, err)
				}
			}

			assert.Equal(t, tt.expectedIP, ip)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}
