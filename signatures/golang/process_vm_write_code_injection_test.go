package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestProcessVmWriteCodeInjection(t *testing.T) {
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
					EventName: "process_vm_writev",
					ProcessID: 109,
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pid",
							},
							Value: interface{}(int32(101)),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1025": {
					Data: nil,
					Event: trace.Event{
						EventName: "process_vm_writev",
						ProcessID: 109,
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pid",
								},
								Value: interface{}(int32(101)),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1025",
						Version:     "1",
						Name:        "Code injection detected using process_vm_writev syscall",
						EventName:   "process_vm_write_inject",
						Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "defense-evasion",
							"Technique":            "Process Injection",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
							"external_id":          "T1055",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - same PID",
			Events: []trace.Event{
				{
					EventName: "process_vm_writev",
					ProcessID: 109,
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pid",
							},
							Value: interface{}(int32(109)),
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
			sig := ProcessVmWriteCodeInjection{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
