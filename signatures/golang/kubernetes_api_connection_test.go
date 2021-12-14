package main

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestK8sApiConnection(t *testing.T) {
	testCases := []struct {
		Name     string
		Events   []types.Event
		Findings map[string]types.Finding
	}{
		{
			Name: "should trigger detection",
			Events: []types.Event{
				external.Event{
					EventName:   "execve",
					ContainerID: "0907ef86d7be",
					Args: []external.Argument{
						{
							ArgMeta: external.ArgMeta{
								Name: "argv",
							},
							Value: []string{"/bin/ls"},
						},
						{
							ArgMeta: external.ArgMeta{
								Name: "envp",
							},
							Value: []string{"CURL_CA_BUNDLE=/cacert.pem", "HOSTNAME=3c5f9dbcb5da", "CURL_RELEASE_TAG=curl-7_76_1", "CURL_GIT_REPO=https://github.com/curl/curl.git", "SHLVL=2", "HOME=/home/curl_user", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/", "KUBERNETES_SERVICE_HOST=1.1.1.1", "CURL_VERSION=7_76_1"},
						},
					},
				},
				external.Event{
					EventName:   "security_socket_connect",
					ContainerID: "0907ef86d7be",
					Args: []external.Argument{
						{
							ArgMeta: external.ArgMeta{
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
			Findings: map[string]types.Finding{
				"TRC-13": {
					Data: map[string]interface{}{
						"ip": "1.1.1.1",
					},
					Context: external.Event{
						EventName:   "security_socket_connect",
						ContainerID: "0907ef86d7be",
						Args: []external.Argument{
							{
								ArgMeta: external.ArgMeta{
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
					SigMetadata: types.SignatureMetadata{
						ID:          "TRC-13",
						Version:     "0.1.0",
						Name:        "Kubernetes API server connection detected",
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
			Events: []types.Event{
				external.Event{
					EventName:   "execve",
					ContainerID: "0907ef86d7be",
					Args: []external.Argument{
						{
							ArgMeta: external.ArgMeta{
								Name: "argv",
							},
							Value: []string{"/bin/ls"},
						},
						{
							ArgMeta: external.ArgMeta{
								Name: "envp",
							},
							Value: []string{"CURL_CA_BUNDLE=/cacert.pem", "HOSTNAME=3c5f9dbcb5da", "CURL_RELEASE_TAG=curl-7_76_1", "CURL_GIT_REPO=https://github.com/curl/curl.git", "SHLVL=2", "HOME=/home/curl_user", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/", "KUBERNETES_SERVICE_HOST=1.1.1.1", "CURL_VERSION=7_76_1"},
						},
					},
				},
				external.Event{
					EventName:   "security_socket_connect",
					ContainerID: "0907ef86d7be",
					Args: []external.Argument{
						{
							ArgMeta: external.ArgMeta{
								Name: "remote_addr",
							},
							Value: map[string]string{"sa_family": "AF_INET", "sin_port": "80", "sin_addr": "169.254.169.254"},
						},
					},
				},
			},
			Findings: map[string]types.Finding{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			holder := signaturestest.FindingsHolder{}

			sig := &K8sApiConnection{}
			err := sig.Init(holder.OnFinding)
			require.NoError(t, err)

			for _, e := range tc.Events {
				err = sig.OnEvent(e)
				require.NoError(t, err)
			}

			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
