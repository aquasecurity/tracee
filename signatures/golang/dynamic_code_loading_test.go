package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDynamicCodeLoading(t *testing.T) {
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
					EventName: "mem_prot_alert",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "alert",
							},
							Value: uint32(trace.ProtAlertMprotectWXToX),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-104": {
					Data: nil,
					Event: trace.Event{
						EventName: "mem_prot_alert",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "alert",
								},
								Value: uint32(trace.ProtAlertMprotectWXToX),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-104",
						Version:     "1",
						Name:        "Dynamic code loading detected",
						EventName:   "dynamic_code_loading",
						Description: "Possible dynamic code loading was detected as the binary's memory is both writable and executable. Writing to an executable allocated memory region could be a technique used by adversaries to run code undetected and without dropping executables.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "defense-evasion",
							"Technique":            "Software Packing",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
							"external_id":          "T1027.002",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong alert",
			Events: []trace.Event{
				{
					EventName: "mem_prot_alert",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "alert",
							},
							Value: uint32(trace.ProtAlertMmapWX),
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
			sig := DynamicCodeLoading{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
