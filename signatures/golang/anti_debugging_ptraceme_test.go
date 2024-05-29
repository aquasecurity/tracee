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

func TestAntiDebuggingPtraceme(t *testing.T) {
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
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "request",
							},
							Value: interface{}(int64(parsers.PTRACE_TRACEME.Value())),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-102": {
					Data: nil,
					Event: trace.Event{
						EventName: "ptrace",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "request",
								},
								Value: interface{}(int64(parsers.PTRACE_TRACEME.Value())),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-102",
						Version:     "1",
						Name:        "Anti-Debugging detected",
						EventName:   "anti_debugging",
						Description: "A process used anti-debugging techniques to block a debugger. Malware use anti-debugging to stay invisible and inhibit analysis of their behavior.",
						Properties: map[string]interface{}{
							"Severity":             1,
							"Category":             "defense-evasion",
							"Technique":            "Debugger Evasion",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391",
							"external_id":          "T1622",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong request",
			Events: []trace.Event{
				{
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "request",
							},
							Value: interface{}(int64(parsers.PTRACE_PEEKTEXT.Value())),
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
			sig := AntiDebuggingPtraceme{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
