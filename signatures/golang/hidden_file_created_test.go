package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestHiddenFileCreated(t *testing.T) {
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
							Value: interface{}("/bin/.bin"),
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
				"TRC-1015": {
					Data: nil,
					Event: trace.Event{
						EventName: "magic_write",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/bin/.bin"),
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
						ID:          "TRC-1015",
						Version:     "1",
						Name:        "Hidden executable creation detected",
						EventName:   "hidden_file_created",
						Description: "A hidden executable (ELF file) was created on disk. This activity could be legitimate; however, it could indicate that an adversary is trying to avoid detection by hiding their programs.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "defense-evasion",
							"Technique":            "Hidden Files and Directories",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--ec8fc7e2-b356-455c-8db5-2e37be158e7d",
							"external_id":          "T1564.001",
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
							Value: interface{}("/bin/.bin"),
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
			Name: "should not trigger detection - not hidden path",
			Events: []trace.Event{
				{
					EventName: "magic_write",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/bin/bin"),
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
			sig := HiddenFileCreated{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
