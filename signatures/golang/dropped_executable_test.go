package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDroppedExecutable(t *testing.T) {
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
					EventName: "magic_write",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/bin/malware"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "bytes",
							},
							Value: interface{}([]byte{127, 69, 76, 70}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1022": {
					Data: map[string]interface{}{"path": "/bin/malware"},
					Event: trace.Event{
						EventName: "magic_write",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/bin/malware"),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "bytes",
								},
								Value: interface{}([]byte{127, 69, 76, 70}),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1022",
						Version:     "1",
						Name:        "New executable dropped",
						EventName:   "dropped_executable",
						Description: "An Executable file was dropped in the system during runtime. Container images are usually built with all binaries needed inside. A dropped binary may indicate that an adversary infiltrated your container.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "defense-evasion",
							"Technique":            "Masquerading",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0",
							"external_id":          "T1036",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - not an ELF",
			Events: []trace.Event{
				{
					EventName: "magic_write",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/bin/not_a_malware"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "bytes",
							},
							Value: interface{}([]byte{0, 0, 0, 0}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - memory path",
			Events: []trace.Event{
				{
					EventName: "magic_write",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/dev/shm/malware"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "bytes",
							},
							Value: interface{}([]byte{127, 69, 76, 70}),
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
			sig := DroppedExecutable{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
