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

func TestKubernetesCertificateTheftAttempt(t *testing.T) {
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
					ProcessName: "malware",
					EventName:   "security_file_open",
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
							Value: interface{}("/etc/kubernetes/pki/ca.crt"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1018": {
					Data: nil,
					Event: trace.Event{
						ProcessName: "malware",
						EventName:   "security_file_open",
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
								Value: interface{}("/etc/kubernetes/pki/ca.crt"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1018",
						Version:     "1",
						Name:        "K8s TLS certificate theft detected",
						EventName:   "k8s_cert_theft",
						Description: "Theft of Kubernetes TLS certificates was detected. TLS certificates are used to establish trust between systems. The Kubernetes certificate is used to to enable secure communication between Kubernetes components, such as kubelet scheduler controller and API Server. An adversary may steal a Kubernetes certificate on a compromised system to impersonate Kubernetes components within the cluster.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "credential-access",
							"Technique":            "Steal Application Access Token",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a",
							"external_id":          "T1528",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "old_path",
							},
							Value: interface{}("/etc/kubernetes/pki/ca.crt"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1018": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "old_path",
								},
								Value: interface{}("/etc/kubernetes/pki/ca.crt"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1018",
						Version:     "1",
						Name:        "K8s TLS certificate theft detected",
						EventName:   "k8s_cert_theft",
						Description: "Theft of Kubernetes TLS certificates was detected. TLS certificates are used to establish trust between systems. The Kubernetes certificate is used to to enable secure communication between Kubernetes components, such as kubelet scheduler controller and API Server. An adversary may steal a Kubernetes certificate on a compromised system to impersonate Kubernetes components within the cluster.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "credential-access",
							"Technique":            "Steal Application Access Token",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a",
							"external_id":          "T1528",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - security_file_open wrong open flags",
			Events: []trace.Event{
				{
					ProcessName: "test",
					EventName:   "security_file_open",
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
							Value: interface{}("/etc/kubernetes/pki/ca.crt"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_file_open wrong path",
			Events: []trace.Event{
				{
					ProcessName: "test",
					EventName:   "security_file_open",
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
							Value: interface{}("/tmp/ca.crt"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_file_open legit proc",
			Events: []trace.Event{
				{
					ProcessName: "kube-apiserver",
					EventName:   "security_file_open",
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
							Value: interface{}("/etc/kubernetes/pki/ca.crt"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_inode_rename wrong path",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "old_path",
							},
							Value: interface{}("/tmp/ca.crt"),
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
			sig := KubernetesCertificateTheftAttempt{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
