package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestSystemRequestKeyConfigModification(t *testing.T) {
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
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/sysrq"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}("O_WRONLY"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1031": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/proc/sys/kernel/sysrq"),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: interface{}("O_WRONLY"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1031",
						Version:     "1",
						Name:        "System request key configuration modification",
						EventName:   "system_request_key_mod",
						Description: "An attempt to modify and activate the System Request Key configuration file was detected. The system request key allows immediate input to the kernel through simple key combinations. Adversaries may use this feature to immediately shut down or restart a system. With read access to kernel logs, host related information such as listing tasks and CPU registers may be disclosed and could be used for container escape.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "privilege-escalation",
							"Technique":            "Escape to Host",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665",
							"external_id":          "T1611",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong open flags",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/sysrq"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}("O_RDONLY"),
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
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/tmp/something"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}("O_WRONLY"),
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
			sig := SystemRequestKeyConfigModification{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
