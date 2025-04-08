package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/pkg/events/pipeline"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestRcdModification(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []pipeline.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - security_file_open file",
			Events: []pipeline.Event{
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
							Value: interface{}("/etc/rc.local"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1026": {
					Data: nil,
					Event: trace.ToProtocol(&pipeline.Event{
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
								Value: interface{}("/etc/rc.local"),
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1026",
						Version:     "1",
						Name:        "Rcd modification detected",
						EventName:   "rcd_modification",
						Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "RC Scripts",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
							"external_id":          "T1037.004",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_file_open directory",
			Events: []pipeline.Event{
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
							Value: interface{}("/etc/rc1.d/job"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1026": {
					Data: nil,
					Event: trace.ToProtocol(&pipeline.Event{
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
								Value: interface{}("/etc/rc1.d/job"),
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1026",
						Version:     "1",
						Name:        "Rcd modification detected",
						EventName:   "rcd_modification",
						Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "RC Scripts",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
							"external_id":          "T1037.004",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename file",
			Events: []pipeline.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/rc.local"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1026": {
					Data: nil,
					Event: trace.ToProtocol(&pipeline.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/rc.local"),
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1026",
						Version:     "1",
						Name:        "Rcd modification detected",
						EventName:   "rcd_modification",
						Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "RC Scripts",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
							"external_id":          "T1037.004",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename directory",
			Events: []pipeline.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/rc1.d/job"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1026": {
					Data: nil,
					Event: trace.ToProtocol(&pipeline.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/rc1.d/job"),
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1026",
						Version:     "1",
						Name:        "Rcd modification detected",
						EventName:   "rcd_modification",
						Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "RC Scripts",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
							"external_id":          "T1037.004",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - sched_process_exec",
			Events: []pipeline.Event{
				{
					EventName: "sched_process_exec",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: "/bin/update-rc.d",
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1026": {
					Data: nil,
					Event: trace.ToProtocol(&pipeline.Event{
						EventName: "sched_process_exec",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: "/bin/update-rc.d",
							},
						},
					}),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1026",
						Version:     "1",
						Name:        "Rcd modification detected",
						EventName:   "rcd_modification",
						Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "RC Scripts",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
							"external_id":          "T1037.004",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - security_file_open wrong path",
			Events: []pipeline.Event{
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
							Value: interface{}("/etc/something"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_file_open wrong open flags",
			Events: []pipeline.Event{
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
							Value: interface{}("/etc/rc.local"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_inode_rename wrong path",
			Events: []pipeline.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/something"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - sched_process_exec",
			Events: []pipeline.Event{
				{
					EventName: "sched_process_exec",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: "/bin/ls",
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
			sig := RcdModification{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(trace.ToProtocol(&e))
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
