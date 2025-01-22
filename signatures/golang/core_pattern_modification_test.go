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

func TestCorePatternModification(t *testing.T) {
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
							Value: interface{}("/proc/sys/kernel/core_pattern"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_WRONLY),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1011": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/proc/sys/kernel/core_pattern"),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: buildFlagArgValue(parsers.O_WRONLY),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1011",
						Version:     "1",
						Name:        "Core dumps configuration file modification detected",
						EventName:   "core_pattern_modification",
						Description: "Modification of the core dump configuration file (core_pattern) detected. Core dumps are usually written to disk when a program crashes. Certain modifications enable container escaping through the kernel core_pattern feature.",
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
							Value: interface{}("/proc/sys/kernel/core_pattern"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_RDONLY),
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
							Value: interface{}("/sys/kernel/something"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_WRONLY),
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
			sig := CorePatternModification{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
