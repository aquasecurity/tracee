package main

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestK8SServiceAccountToken(t *testing.T) {
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
							Value: interface{}("/var/run/secrets/kubernetes.io/serviceaccount/token"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-108": {
					Data: nil,
					Event: trace.Event{
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
								Value: interface{}("/var/run/secrets/kubernetes.io/serviceaccount/token"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-108",
						Version:     "1",
						Name:        "K8s service account token file read",
						EventName:   "k8s_service_account_token",
						Description: "The Kubernetes service account token file was read on your container. This token is used to communicate with the Kubernetes API Server. Adversaries may try to communicate with the API Server to steal information and/or credentials, or even run more containers and laterally extend their grip on the systems.",
						Properties: map[string]interface{}{
							"Severity":             0,
							"Category":             "credential-access",
							"Technique":            "Exploitation for Credential Access",
							"Kubernetes_Technique": "Container service account",
							"id":                   "attack-pattern--9c306d8d-cde7-4b4c-b6e8-d0bb16caca36",
							"external_id":          "T1212",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong open flags",
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
							Value: interface{}("/var/run/secrets/kubernetes.io/serviceaccount/token"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - wrong path",
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
							Value: interface{}("/tmp/token"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - legit proc",
			Events: []trace.Event{
				{
					ProcessName: "flanneld",
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
							Value: interface{}("/var/run/secrets/kubernetes.io/serviceaccount/token"),
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
			sig := K8SServiceAccountToken{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}

func TestK8SServiceAccountTokenRegex(t *testing.T) {
	re := regexp.MustCompile(tokenPathRegexString)

	validPaths := []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/token1234token",
		"/mnt/data/secrets/kubernetes.io/serviceaccount/my-token",
		"/any/secrets/kubernetes.io/serviceaccount/1234token",
	}

	invalidPaths := []string{
		"/var/run/secrets/kubernetes.io/serviceaccounttoken",      // no slash after serviceaccount
		"/var/run/secrets/kubernetes.io/serviceaccount-my-token",  // no slash after serviceaccount
		"/var/run/secrets/kubernetes.io/serviceaccount/token1234", // not ending with 'token'
		"/var/run/secrets/kubernetesXio/serviceaccount/token",     // typo in 'kubernetes.io'
		"/var/run/secrets/kubernetes/io/serviceaccount/token",     // typo in 'kubernetes.io'

		"/tmp/token", // not a k8s path
	}

	for _, p := range validPaths {
		assert.True(t, re.MatchString(p), "regex should match: %s", p)
	}

	for _, p := range invalidPaths {
		assert.False(t, re.MatchString(p), "regex should not match: %s", p)
	}
}
