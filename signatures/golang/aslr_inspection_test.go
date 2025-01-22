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

func TestAslrInspection(t *testing.T) {
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
								Name: "flags",
							},
							Value: interface{}(buildFlagArgValue(parsers.O_RDONLY)),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/randomize_va_space"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-109": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: interface{}(buildFlagArgValue(parsers.O_RDONLY)),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/proc/sys/kernel/randomize_va_space"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-109",
						Version:     "1",
						Name:        "ASLR inspection detected",
						EventName:   "aslr_inspection",
						Description: "The ASLR (address space layout randomization) configuration was inspected. ASLR is used by Linux to prevent memory vulnerabilities. An adversary may want to inspect and change the ASLR configuration in order to avoid detection.",
						Properties: map[string]interface{}{
							"Severity":             0,
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
			Name: "should not trigger detection - wrong open flags",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/randomize_va_space"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}(buildFlagArgValue(parsers.O_WRONLY)),
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
								Name: "flags",
							},
							Value: interface{}(buildFlagArgValue(parsers.O_RDONLY)),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/yo"),
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
			sig := AslrInspection{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
