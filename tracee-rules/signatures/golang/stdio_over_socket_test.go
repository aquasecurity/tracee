package main

import (
	"testing"

	tracee "github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStdioOverSocket(t *testing.T) {
	noFindings := map[string]types.Finding{}
	md := types.SignatureMetadata{
		ID:          "TRC-1",
		Version:     "0.1.0",
		Name:        "Standard Input/Output Over Socket",
		Description: "Redirection of process's standard input/output to socket",
		Tags:        []string{"linux", "container"},
		Properties: map[string]interface{}{
			"Severity":     3,
			"MITRE ATT&CK": "Persistence: Server Software Component",
		},
	}

	testCases := []struct {
		Name     string
		Events   []types.Event
		Findings map[string]types.Finding
	}{
		{
			Name: "A",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: map[string]types.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					SigMetadata: md,
					Context: tracee.Event{
						ProcessID: 45,
						EventName: "dup2",
						Args: []tracee.Argument{
							{
								ArgMeta: tracee.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: tracee.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
						},
					},
				},
			},
		},
		{
			Name: "B",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: map[string]types.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					SigMetadata: md,
					Context: tracee.Event{
						ProcessID: 45,
						EventName: "dup2",
						Args: []tracee.Argument{
							{
								ArgMeta: tracee.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: tracee.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
						},
					},
				},
			},
		},
		{
			Name: "C",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				tracee.Event{
					ProcessID:   45,
					EventName:   "dup",
					ReturnValue: 1,
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
					},
				},
			},
			Findings: map[string]types.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   1,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					Context: tracee.Event{
						ProcessID:   45,
						EventName:   "dup",
						ReturnValue: 1,
						Args: []tracee.Argument{
							{
								ArgMeta: tracee.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
						},
					},
					SigMetadata: md,
				},
			},
		},
		{
			Name: "D",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup3",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "flags",
							},
							Value: "SOMEFLAGS",
						},
					},
				},
			},
			Findings: map[string]types.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					Context: tracee.Event{
						ProcessID: 45,
						EventName: "dup3",
						Args: []tracee.Argument{
							{
								ArgMeta: tracee.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: tracee.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
							{
								ArgMeta: tracee.ArgMeta{
									Name: "flags",
								},
								Value: "SOMEFLAGS",
							},
						},
					},
					SigMetadata: md,
				},
			},
		},
		{
			Name: "E",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: noFindings,
		},
		{
			Name: "F",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "close",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "fd",
							},
							Value: int32(5),
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: noFindings,
		},
		{
			Name: "G",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				tracee.Event{
					ProcessID: 22,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: noFindings,
		},
		{
			Name: "H",
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET6", "sin6_port": "443", "sin6_addr": "2001:67c:1360:8001::2f", "sin6_scopeid": "0", "sin6_flowinfo": "0"},
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: map[string]types.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "2001:67c:1360:8001::2f",
						"port": "443",
					},
					Context: tracee.Event{
						ProcessID: 45,
						EventName: "dup2",
						Args: []tracee.Argument{
							{
								ArgMeta: tracee.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: tracee.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
						},
					},
					SigMetadata: md,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			holder := signaturestest.FindingsHolder{}
			sig := stdioOverSocket{}
			sig.Init(holder.OnFinding)

			for _, e := range tc.Events {
				err := sig.OnEvent(e)
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
