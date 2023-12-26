package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestProcFopsHooking(t *testing.T) {
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
					EventName: "hooked_proc_fops",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_fops_pointers",
							},
							Value: interface{}([]trace.HookedSymbolData{
								{SymbolName: "struct file_operations pointer", ModuleOwner: "hidden"},
								{SymbolName: "iterate_shared", ModuleOwner: "phide"},
							}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1020": {
					Data: map[string]interface{}{"Hooked proc file operations": []trace.HookedSymbolData{
						{SymbolName: "struct file_operations pointer", ModuleOwner: "hidden"},
						{SymbolName: "iterate_shared", ModuleOwner: "phide"},
					}},
					Event: trace.Event{
						EventName: "hooked_proc_fops",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "hooked_fops_pointers",
								},
								Value: interface{}([]trace.HookedSymbolData{
									{SymbolName: "struct file_operations pointer", ModuleOwner: "hidden"},
									{SymbolName: "iterate_shared", ModuleOwner: "phide"},
								}),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1020",
						Version:     "1",
						Name:        "File operations hooking on proc filesystem detected",
						EventName:   "proc_fops_hooking",
						Description: "File operations hooking on proc filesystem detected. The proc filesystem is an interface for the running processes as files. This allows programs like `ps` and `top` to check what are the running processes. File operations are the functions defined on a file or directory. File operations hooking includes replacing the default function used to perform a basic task on files and directories like enumerating files. By hooking the file operations of /proc an adversary gains control on certain system function, such as file listing or other basic function performed by the operation system. The adversary may also hijack the execution flow and execute it's own code. File operation hooking is considered a malicious behavior that is performed by rootkits and may indicate that the host's kernel has been compromised. Hidden modules are marked as hidden symbol owners and indicate further malicious activity of an adversary.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "defense-evasion",
							"Technique":            "Rootkit",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b",
							"external_id":          "T1014",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - empty slice of symbols",
			Events: []trace.Event{
				{
					EventName: "hooked_proc_fops",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_fops_pointers",
							},
							Value: interface{}([]trace.HookedSymbolData{}),
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
			sig := ProcFopsHooking{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
