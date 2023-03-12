package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestPtraceCodeInjection(t *testing.T) {
	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]detect.Finding
	}{
		{
			Name: "should trigger detection - PTRACE_POKETEXT",
			Events: []trace.Event{
				{
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "request",
							},
							Value: interface{}("PTRACE_POKETEXT"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-103": {
					Data: nil,
					Event: trace.Event{
						EventName: "ptrace",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "request",
								},
								Value: interface{}("PTRACE_POKETEXT"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-103",
						Version:     "1",
						Name:        "Code injection detected using ptrace",
						EventName:   "ptrace_code_injection",
						Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "defense-evasion",
							"Technique":            "Ptrace System Calls",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--ea016b56-ae0e-47fe-967a-cc0ad51af67f",
							"external_id":          "T1055.008",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - PTRACE_POKEDATA",
			Events: []trace.Event{
				{
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "request",
							},
							Value: interface{}("PTRACE_POKEDATA"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-103": {
					Data: nil,
					Event: trace.Event{
						EventName: "ptrace",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "request",
								},
								Value: interface{}("PTRACE_POKEDATA"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-103",
						Version:     "1",
						Name:        "Code injection detected using ptrace",
						EventName:   "ptrace_code_injection",
						Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "defense-evasion",
							"Technique":            "Ptrace System Calls",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--ea016b56-ae0e-47fe-967a-cc0ad51af67f",
							"external_id":          "T1055.008",
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
							Value: interface{}("PTRACE_PEEKTEXT"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			holder := signaturestest.FindingsHolder{}
			sig := PtraceCodeInjection{}
			sig.Init(holder.OnFinding)

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
