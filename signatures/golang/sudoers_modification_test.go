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

func TestSudoersModification(t *testing.T) {
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
								Name: "pathname",
							},
							Value: interface{}("/etc/sudoers"),
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
				"TRC-1028": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/etc/sudoers"),
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
						ID:          "TRC-1028",
						Version:     "1",
						Name:        "Sudoers file modification detected",
						EventName:   "sudoers_modification",
						Description: "The sudoers file was modified. The sudoers file is a configuration file which controls the permissions and options of the sudo feature. Adversaries may alter the sudoers file to elevate privileges, execute commands as other users or spawn processes with higher privileges.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "privilege-escalation",
							"Technique":            "Sudo and Sudo Caching",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0",
							"external_id":          "T1548.003",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_file_open dir",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/etc/sudoers.d/amnon"),
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
				"TRC-1028": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/etc/sudoers.d/amnon"),
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
						ID:          "TRC-1028",
						Version:     "1",
						Name:        "Sudoers file modification detected",
						EventName:   "sudoers_modification",
						Description: "The sudoers file was modified. The sudoers file is a configuration file which controls the permissions and options of the sudo feature. Adversaries may alter the sudoers file to elevate privileges, execute commands as other users or spawn processes with higher privileges.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "privilege-escalation",
							"Technique":            "Sudo and Sudo Caching",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0",
							"external_id":          "T1548.003",
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
							Value: interface{}("/etc/sudoers"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1028": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/sudoers"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1028",
						Version:     "1",
						Name:        "Sudoers file modification detected",
						EventName:   "sudoers_modification",
						Description: "The sudoers file was modified. The sudoers file is a configuration file which controls the permissions and options of the sudo feature. Adversaries may alter the sudoers file to elevate privileges, execute commands as other users or spawn processes with higher privileges.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "privilege-escalation",
							"Technique":            "Sudo and Sudo Caching",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0",
							"external_id":          "T1548.003",
						},
					},
				},
			},
		},
		{
			Name: "should trigger detection - security_inode_rename dir",
			Events: []trace.Event{
				{
					EventName: "security_inode_rename",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "new_path",
							},
							Value: interface{}("/etc/sudoers.d/amnon"),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1028": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_inode_rename",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "new_path",
								},
								Value: interface{}("/etc/sudoers.d/amnon"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1028",
						Version:     "1",
						Name:        "Sudoers file modification detected",
						EventName:   "sudoers_modification",
						Description: "The sudoers file was modified. The sudoers file is a configuration file which controls the permissions and options of the sudo feature. Adversaries may alter the sudoers file to elevate privileges, execute commands as other users or spawn processes with higher privileges.",
						Properties: map[string]interface{}{
							"Severity":             2,
							"Category":             "privilege-escalation",
							"Technique":            "Sudo and Sudo Caching",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0",
							"external_id":          "T1548.003",
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
							Value: interface{}("/etc/sudoers"),
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
							Value: buildFlagArgValue(parsers.O_WRONLY),
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
			sig := SudoersModification{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
