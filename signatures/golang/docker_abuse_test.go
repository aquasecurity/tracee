package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDockerAbuse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - security_file_open",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Container: trace.Container{ID: "dockercontainer"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_WRONLY),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/var/run/docker.sock"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1019": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Container: trace.Container{ID: "dockercontainer"},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: buildFlagArgValue(parsers.O_WRONLY),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/var/run/docker.sock"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1019",
						Version:     "1",
						Name:        "Docker socket abuse detected",
						EventName:   "docker_abuse",
						Description: "An attempt to abuse the Docker UNIX socket inside a container was detected. docker.sock is the UNIX socket that Docker uses as the entry point to the Docker API. Adversaries may attempt to abuse this socket to compromise the system.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "privilege-escalation",
							"Technique":            "Exploitation for Privilege Escalation",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
							"external_id":          "T1068",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_socket_connect",
			Events: []trace.Event{
				{
					EventName: "security_socket_connect",
					Container: trace.Container{ID: "dockercontainer"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_UNIX", "sun_path": "/var/run/docker.sock"},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1019": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_socket_connect",
						Container: trace.Container{ID: "dockercontainer"},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "remote_addr",
								},
								Value: map[string]string{"sa_family": "AF_UNIX", "sun_path": "/var/run/docker.sock"},
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1019",
						Version:     "1",
						Name:        "Docker socket abuse detected",
						EventName:   "docker_abuse",
						Description: "An attempt to abuse the Docker UNIX socket inside a container was detected. docker.sock is the UNIX socket that Docker uses as the entry point to the Docker API. Adversaries may attempt to abuse this socket to compromise the system.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "privilege-escalation",
							"Technique":            "Exploitation for Privilege Escalation",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
							"external_id":          "T1068",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - security_file_open wrong path",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Container: trace.Container{ID: "dockercontainer"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_WRONLY),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/var/docker.socket"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_file_open wrong open flags",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Container: trace.Container{ID: "dockercontainer"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_RDONLY),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/var/run/docker.sock"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_socket_connect wrong addr",
			Events: []trace.Event{
				{
					EventName: "security_socket_connect",
					Container: trace.Container{ID: "dockercontainer"},
					Args: []trace.Argument{
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
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			holder := signaturestest.FindingsHolder{}
			sig := DockerAbuse{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
