package main

import (
	"testing"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStdioOverSocket(t *testing.T) {
	noFindings := map[string]detect.Finding{}
	md := detect.SignatureMetadata{
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
		Events   []trace.Event
		Findings map[string]detect.Finding
	}{
		{
			Name: "A",
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				{
					ProcessID: 45,
					EventName: "dup2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					SigMetadata: md,
					Event: trace.Event{
						ProcessID: 45,
						EventName: "dup2",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
						},
					}.ToProtocol(),
				},
			},
		},
		{
			Name: "B",
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				{
					ProcessID: 45,
					EventName: "dup2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					SigMetadata: md,
					Event: trace.Event{
						ProcessID: 45,
						EventName: "dup2",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
						},
					}.ToProtocol(),
				},
			},
		},
		{
			Name: "C",
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				{
					ProcessID:   45,
					EventName:   "dup",
					ReturnValue: 1,
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   1,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					Event: trace.Event{
						ProcessID:   45,
						EventName:   "dup",
						ReturnValue: 1,
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
						},
					}.ToProtocol(),
					SigMetadata: md,
				},
			},
		},
		{
			Name: "D",
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				{
					ProcessID: 45,
					EventName: "dup3",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: "SOMEFLAGS",
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "10.225.0.2",
						"port": "53",
					},
					Event: trace.Event{
						ProcessID: 45,
						EventName: "dup3",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: "SOMEFLAGS",
							},
						},
					}.ToProtocol(),
					SigMetadata: md,
				},
			},
		},
		{
			Name: "E",
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "dup2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
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
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				{
					ProcessID: 45,
					EventName: "close",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "fd",
							},
							Value: int32(5),
						},
					},
				},
				{
					ProcessID: 45,
					EventName: "dup2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
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
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
				{
					ProcessID: 22,
					EventName: "dup2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
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
			Events: []trace.Event{
				{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET6", "sin6_port": "443", "sin6_addr": "2001:67c:1360:8001::2f", "sin6_scopeid": "0", "sin6_flowinfo": "0"},
						},
					},
				},
				{
					ProcessID: 45,
					EventName: "dup2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1": {
					Data: map[string]interface{}{
						"fd":   0,
						"ip":   "2001:67c:1360:8001::2f",
						"port": "443",
					},
					Event: trace.Event{
						ProcessID: 45,
						EventName: "dup2",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "oldfd",
								},
								Value: int32(5),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
						},
					}.ToProtocol(),
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
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
