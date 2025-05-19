package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events/pipeline"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestStdioOverSocket(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []pipeline.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - security_socket_connect",
			Events: []pipeline.Event{
				{
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(0),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-101": {
					Data: map[string]interface{}{
						"File descriptor": 0,
						"IP address":      "10.225.0.2",
						"Port":            "53",
					},
					Event: trace.ToProtocol(&pipeline.Event{
						EventName: "security_socket_connect",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "sockfd",
								},
								Value: int32(0),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "remote_addr",
								},
								Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-101",
						Version:     "2",
						Name:        "Process standard input/output over socket detected",
						EventName:   "stdio_over_socket",
						Description: "A process has its standard input/output redirected to a socket. This behavior is the base of a Reverse Shell attack, which is when an interactive shell being invoked from a target machine back to the attacker's machine, giving it interactive control over the target. Adversaries may use a Reverse Shell to retain control over a compromised target while bypassing security measures like network firewalls.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "execution",
							"Technique":            "Unix Shell",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--a9d4b653-6915-42af-98b2-5758c4ceee56",
							"external_id":          "T1059.004",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - socket_dup",
			Events: []pipeline.Event{
				{
					EventName: "socket_dup",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-101": {
					Data: map[string]interface{}{
						"File descriptor": 0,
						"IP address":      "10.225.0.2",
						"Port":            "53",
					},
					Event: trace.ToProtocol(&pipeline.Event{
						EventName: "socket_dup",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "newfd",
								},
								Value: int32(0),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "remote_addr",
								},
								Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-101",
						Version:     "2",
						Name:        "Process standard input/output over socket detected",
						EventName:   "stdio_over_socket",
						Description: "A process has its standard input/output redirected to a socket. This behavior is the base of a Reverse Shell attack, which is when an interactive shell being invoked from a target machine back to the attacker's machine, giving it interactive control over the target. Adversaries may use a Reverse Shell to retain control over a compromised target while bypassing security measures like network firewalls.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "execution",
							"Technique":            "Unix Shell",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--a9d4b653-6915-42af-98b2-5758c4ceee56",
							"external_id":          "T1059.004",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - security_socket_connect wrong FD",
			Events: []pipeline.Event{
				{
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(3),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_socket_connect legit port",
			Events: []pipeline.Event{
				{
					EventName: "security_socket_connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(1),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "0", "sin_addr": ""},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - socket_dup wrong FD",
			Events: []pipeline.Event{
				{
					EventName: "socket_dup",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(3),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "53", "sin_addr": "10.225.0.2"},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - socket_dup legit port",
			Events: []pipeline.Event{
				{
					EventName: "socket_dup",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "newfd",
							},
							Value: int32(1),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "0", "sin_addr": ""},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			holder := signaturestest.FindingsHolder{}
			sig := StdioOverSocket{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(trace.ToProtocol(&e))
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
