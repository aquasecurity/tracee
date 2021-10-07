package main

import (
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestK8sApiConnection(t *testing.T) {
	SigTests := []signaturestest.SigTest{
		{
			Events: []types.Event{
				tracee.Event{
					EventName:   "execve",
					ContainerID: "0907ef86d7be",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "argv",
							},
							Value: []string{"/bin/ls"},
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "envp",
							},
							Value: []string{"CURL_CA_BUNDLE=/cacert.pem", "HOSTNAME=3c5f9dbcb5da", "CURL_RELEASE_TAG=curl-7_76_1", "CURL_GIT_REPO=https://github.com/curl/curl.git", "SHLVL=2", "HOME=/home/curl_user", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/", "KUBERNETES_SERVICE_HOST=1.1.1.1", "CURL_VERSION=7_76_1"},
						},
					},
				},
				tracee.Event{
					EventName:   "security_socket_connect",
					ContainerID: "0907ef86d7be",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '80','sin_addr': '1.1.1.1'}",
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName:   "execve",
					ContainerID: "0907ef86d7be",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "argv",
							},
							Value: []string{"/bin/ls"},
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "envp",
							},
							Value: []string{"CURL_CA_BUNDLE=/cacert.pem", "HOSTNAME=3c5f9dbcb5da", "CURL_RELEASE_TAG=curl-7_76_1", "CURL_GIT_REPO=https://github.com/curl/curl.git", "SHLVL=2", "HOME=/home/curl_user", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/", "KUBERNETES_SERVICE_HOST=1.1.1.1", "CURL_VERSION=7_76_1"},
						},
					},
				},
				tracee.Event{
					EventName:   "security_socket_connect",
					ContainerID: "0907ef86d7be",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '80','sin_addr': '169.254.169.254'}",
						},
					},
				},
			},
			Expect: false,
		},
	}

	for _, st := range SigTests {
		sig := K8sApiConnection{}
		st.Init(&sig)
		for _, e := range st.Events {
			err := sig.OnEvent(e)
			if err != nil {
				t.Error(err, st)
			}
		}

		if st.Expect != st.Status {
			t.Error("Unexpected result", st)
		}
	}
}
