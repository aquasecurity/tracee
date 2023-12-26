package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestK8sApiConnection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection",
			Events: []trace.Event{
				{
					EventName: "sched_process_exec",
					Container: trace.Container{ID: "0907ef86d7be"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: []string{"/bin/ls"},
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "env",
							},
							Value: []string{"CURL_CA_BUNDLE=/cacert.pem", "HOSTNAME=3c5f9dbcb5da", "CURL_RELEASE_TAG=curl-7_76_1", "CURL_GIT_REPO=https://github.com/curl/curl.git", "SHLVL=2", "HOME=/home/curl_user", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/", "KUBERNETES_SERVICE_HOST=1.1.1.1", "CURL_VERSION=7_76_1"},
						},
					},
				},
				{
					EventName: "security_socket_connect",
					Container: trace.Container{ID: "0907ef86d7be"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{
								"sa_family": "AF_INET",
								"sin_port":  "80",
								"sin_addr":  "1.1.1.1",
							},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1013": {
					Data: map[string]interface{}{
						"ip": "1.1.1.1",
					},
					Event: trace.Event{
						EventName: "security_socket_connect",
						Container: trace.Container{ID: "0907ef86d7be"},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "remote_addr",
								},
								Value: map[string]string{
									"sa_family": "AF_INET",
									"sin_port":  "80",
									"sin_addr":  "1.1.1.1",
								},
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1013",
						Version:     "0.1.0",
						Name:        "Kubernetes API server connection detected",
						EventName:   "k8s_api_connection",
						Description: "A connection to the kubernetes API server was detected. The K8S API server is the brain of your K8S cluster, adversaries may try and communicate with the K8S API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.",
						Tags:        []string{"container"},
						Properties: map[string]interface{}{
							"Severity":     1,
							"MITRE ATT&CK": "Discovery: Cloud Service Discovery",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection",
			Events: []trace.Event{
				{
					EventName: "sched_process_exec",
					Container: trace.Container{ID: "0907ef86d7be"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: []string{"/bin/ls"},
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "env",
							},
							Value: []string{"CURL_CA_BUNDLE=/cacert.pem", "HOSTNAME=3c5f9dbcb5da", "CURL_RELEASE_TAG=curl-7_76_1", "CURL_GIT_REPO=https://github.com/curl/curl.git", "SHLVL=2", "HOME=/home/curl_user", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/", "KUBERNETES_SERVICE_HOST=1.1.1.1", "CURL_VERSION=7_76_1"},
						},
					},
				},
				{
					EventName: "security_socket_connect",
					Container: trace.Container{ID: "0907ef86d7be"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "80", "sin_addr": "169.254.169.254"},
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

			sig := &K8sApiConnection{}
			err := sig.Init(detect.SignatureContext{Callback: holder.OnFinding})
			require.NoError(t, err)

			for _, e := range tc.Events {
				err = sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}

			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
