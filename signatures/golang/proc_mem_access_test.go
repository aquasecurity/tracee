package main

import (
	"testing"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcMemAccess(t *testing.T) {
	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]detect.Finding
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
							Value: interface{}("O_RDONLY"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/543/mem"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-128": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: interface{}("O_RDONLY"),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/proc/543/mem"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-128",
						Version:     "1",
						Name:        "Process memory access detected",
						Description: "Process memory access detected. Adversaries may access other processes memory to steal credentials and secrets.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "credential-access",
							"Technique":            "Proc Filesystem",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--3120b9fa-23b8-4500-ae73-09494f607b7d",
							"external_id":          "T1003.007",
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
								Name: "flags",
							},
							Value: interface{}("O_WRONLY"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/543/mem"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{},
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
							Value: interface{}("O_RDONLY"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/var/543/mem"),
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
			sig := ProcMemAccess{}
			sig.Init(holder.OnFinding)

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
