package main

import (
	"testing"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskMount(t *testing.T) {
	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]detect.Finding
	}{
		{
			Name: "should trigger detection",
			Events: []trace.Event{
				{
					ProcessName: "mal",
					ThreadID:    8,
					EventName:   "security_sb_mount",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "dev_name",
							},
							Value: interface{}("/dev/sda1"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1014": {
					Data: nil,
					Event: trace.Event{
						ProcessName: "mal",
						ThreadID:    8,
						EventName:   "security_sb_mount",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "dev_name",
								},
								Value: interface{}("/dev/sda1"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1014",
						Version:     "1",
						Name:        "Container device mount detected",
						EventName:   "disk_mount",
						Description: "Container device filesystem mount detected. A mount of a host device filesystem can be exploited by adversaries to perform container escape.",
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
			Name: "should not trigger detection - runc",
			Events: []trace.Event{
				{
					ProcessName: "runc:[init]",
					ThreadID:    1,
					EventName:   "security_sb_mount",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "dev_name",
							},
							Value: interface{}("/dev/sda1"),
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
					ProcessName: "runc:[init]",
					ThreadID:    8,
					EventName:   "security_sb_mount",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "dev_name",
							},
							Value: interface{}("/tmp/something"),
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
			sig := DiskMount{}
			sig.Init(holder.OnFinding)

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
