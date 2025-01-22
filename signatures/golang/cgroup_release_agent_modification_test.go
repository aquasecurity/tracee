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

func TestCgroupReleaseAgentModification(t *testing.T) {
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
								Name: "pathname",
							},
							Value: interface{}("/tmp/cgrp/release_agent"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}(buildFlagArgValue(parsers.O_WRONLY)),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1010": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/tmp/cgrp/release_agent"),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: interface{}(buildFlagArgValue(parsers.O_WRONLY)),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1010",
						Version:     "1",
						Name:        "Cgroups release agent file modification",
						EventName:   "cgroup_release_agent",
						Description: "An attempt to modify Cgroup release agent file was detected. Cgroups are a Linux kernel feature which limits the resource usage of a set of processes. Adversaries may use this feature for container escaping.",
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
			Name: "should trigger detection - security_inode_rename",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/tmp/cgrp/release_agent"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1010": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/tmp/cgrp/release_agent"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1010",
						Version:     "1",
						Name:        "Cgroups release agent file modification",
						EventName:   "cgroup_release_agent",
						Description: "An attempt to modify Cgroup release agent file was detected. Cgroups are a Linux kernel feature which limits the resource usage of a set of processes. Adversaries may use this feature for container escaping.",
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
			Name: "should not trigger detection - security_file_open wrong open flags",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/tmp/cgrp/release_agent"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}(buildFlagArgValue(parsers.O_RDONLY)),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - security_file_open wrong path",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/tmp/something"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}(buildFlagArgValue(parsers.O_WRONLY)),
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
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			holder := signaturestest.FindingsHolder{}
			sig := CgroupReleaseAgentModification{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
