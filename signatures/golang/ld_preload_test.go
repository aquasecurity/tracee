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

func TestLdPreload(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - security_file_open",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_WRONLY),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/etc/ld.so.preload"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-107": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: buildFlagArgValue(parsers.O_WRONLY),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/etc/ld.so.preload"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-107",
						Version:     "1",
						Name:        "LD_PRELOAD code injection detected",
						EventName:   "ld_preload",
						Description: "LD_PRELOAD usage was detected. LD_PRELOAD lets you load your library before any other library, allowing you to hook functions in a process. Adversaries may use this technique to change your applications' behavior or load their own programs.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Hijack Execution Flow",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
							"external_id":          "T1574",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/ld.so.preload"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-107": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/ld.so.preload"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-107",
						Version:     "1",
						Name:        "LD_PRELOAD code injection detected",
						EventName:   "ld_preload",
						Description: "LD_PRELOAD usage was detected. LD_PRELOAD lets you load your library before any other library, allowing you to hook functions in a process. Adversaries may use this technique to change your applications' behavior or load their own programs.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Hijack Execution Flow",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
							"external_id":          "T1574",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - sched_process_exec",
			Events: []trace.Event{
				{
					EventName: "sched_process_exec",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "env",
							},
							Value: interface{}([]string{"FOO=BAR", "LD_PRELOAD=/something"}),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"ls"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-107": {
					Data: map[string]interface{}{"LD_PRELOAD": "LD_PRELOAD=/something"},
					Event: trace.Event{
						EventName: "sched_process_exec",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "env",
								},
								Value: interface{}([]string{"FOO=BAR", "LD_PRELOAD=/something"}),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"ls"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-107",
						Version:     "1",
						Name:        "LD_PRELOAD code injection detected",
						EventName:   "ld_preload",
						Description: "LD_PRELOAD usage was detected. LD_PRELOAD lets you load your library before any other library, allowing you to hook functions in a process. Adversaries may use this technique to change your applications' behavior or load their own programs.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Hijack Execution Flow",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
							"external_id":          "T1574",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - security_file_open wrong path",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_WRONLY),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/var/lib/some_file"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_file_open wrong open flags",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: buildFlagArgValue(parsers.O_RDONLY),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/etc/ld.so.preload"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_inode_rename wrong path",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/tmp/something"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - sched_process_exec",
			Events: []trace.Event{
				{
					EventName: "sched_process_exec",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "env",
							},
							Value: interface{}([]string{"FOO=BAR", "LD_LOAD=/something"}),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"ls"}),
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
			sig := LdPreload{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
