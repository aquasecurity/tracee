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

func TestScheduledTaskModification(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - security_file_open file",
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
							Value: interface{}("/etc/crontab"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1027": {
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
								Value: interface{}("/etc/crontab"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1027",
						Version:     "1",
						Name:        "Scheduled tasks modification detected",
						EventName:   "scheduled_task_mod",
						Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Cron",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
							"external_id":          "T1053.003",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_file_open directory",
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
							Value: interface{}("/etc/cron.d/job"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1027": {
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
								Value: interface{}("/etc/cron.d/job"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1027",
						Version:     "1",
						Name:        "Scheduled tasks modification detected",
						EventName:   "scheduled_task_mod",
						Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Cron",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
							"external_id":          "T1053.003",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename file",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/crontab"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1027": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/crontab"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1027",
						Version:     "1",
						Name:        "Scheduled tasks modification detected",
						EventName:   "scheduled_task_mod",
						Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Cron",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
							"external_id":          "T1053.003",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename directory",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/cron.d/job"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1027": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/cron.d/job"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1027",
						Version:     "1",
						Name:        "Scheduled tasks modification detected",
						EventName:   "scheduled_task_mod",
						Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Cron",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
							"external_id":          "T1053.003",
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
								Name: "pathname",
							},
							Value: "/bin/crontab",
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1027": {
					Data: nil,
					Event: trace.Event{
						EventName: "sched_process_exec",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: "/bin/crontab",
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1027",
						Version:     "1",
						Name:        "Scheduled tasks modification detected",
						EventName:   "scheduled_task_mod",
						Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "persistence",
							"Technique":            "Cron",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
							"external_id":          "T1053.003",
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
							Value: interface{}("/etc/crontab"),
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
							Value: interface{}("/var/lib/some_file"),
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
			sig := ScheduledTaskModification{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
