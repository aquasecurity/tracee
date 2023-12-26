package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestFilelessExecution(t *testing.T) {
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
					EventName: "sched_process_exec",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: "memfd://something",
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-105": {
					Data: nil,
					Event: trace.Event{
						EventName: "sched_process_exec",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: "memfd://something",
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-105",
						Version:     "1",
						Name:        "Fileless execution detected",
						EventName:   "fileless_execution",
						Description: "Fileless execution was detected. Executing a process from memory instead from a file in the filesystem may indicate that an adversary is trying to avoid execution detection.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "defense-evasion",
							"Technique":            "Reflective Code Loading",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--4933e63b-9b77-476e-ab29-761bc5b7d15a",
							"external_id":          "T1620",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong path",
			Events: []trace.Event{
				{
					EventName: "sched_process_exec",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: "/bin/something",
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
			sig := FilelessExecution{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
