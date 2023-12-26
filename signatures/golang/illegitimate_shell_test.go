package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestIllegitimateShell(t *testing.T) {
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
					EventName:   "security_bprm_check",
					ProcessName: "apache2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/bin/dash"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1016": {
					Data: nil,
					Event: trace.Event{
						EventName:   "security_bprm_check",
						ProcessName: "apache2",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/bin/dash"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1016",
						Version:     "1",
						Name:        "Web server spawned a shell",
						EventName:   "illegitimate_shell",
						Description: "A web-server program on your server spawned a shell program. Shell is the linux command-line program, web servers usually don't run shell programs, so this alert might indicate an adversary is exploiting a web server program to gain command execution on the server.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "initial-access",
							"Technique":            "Exploit Public-Facing Application",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
							"external_id":          "T1190",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong path",
			Events: []trace.Event{
				{
					EventName:   "security_bprm_check",
					ProcessName: "apache2",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/bin/ls"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - wrong process name",
			Events: []trace.Event{
				{
					EventName:   "security_bprm_check",
					ProcessName: "bash",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/bin/dash"),
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
			sig := IllegitimateShell{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
