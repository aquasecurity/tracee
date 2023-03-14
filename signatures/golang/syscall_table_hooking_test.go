package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestSyscallTableHooking(t *testing.T) {
	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]detect.Finding
	}{
		{
			Name: "should trigger detection",
			Events: []trace.Event{
				{
					EventName: "hooked_syscalls",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_syscalls",
							},
							Value: interface{}([]trace.HookedSymbolData{
								{SymbolName: "kill", ModuleOwner: "hidden"},
								{SymbolName: "getdents", ModuleOwner: "hidden"},
								{SymbolName: "getdents64", ModuleOwner: "hidden"},
							}),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-1030": {
					Data: map[string]interface{}{"Hooked syscalls": []trace.HookedSymbolData{
						{SymbolName: "kill", ModuleOwner: "hidden"},
						{SymbolName: "getdents", ModuleOwner: "hidden"},
						{SymbolName: "getdents64", ModuleOwner: "hidden"},
					}},
					Event: trace.Event{
						EventName: "hooked_syscalls",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "hooked_syscalls",
								},
								Value: interface{}([]trace.HookedSymbolData{
									{SymbolName: "kill", ModuleOwner: "hidden"},
									{SymbolName: "getdents", ModuleOwner: "hidden"},
									{SymbolName: "getdents64", ModuleOwner: "hidden"},
								}),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-1030",
						Version:     "1",
						Name:        "Syscall table hooking detected",
						EventName:   "syscall_hooking",
						Description: "Syscall table hooking detected. Syscalls (system calls) are the interface between user applications and the kernel. By hooking the syscall table an adversary gains control on certain system function, such as file writing and reading or other basic function performed by the operation system. The adversary may also hijack the execution flow and execute it's own code. Syscall table hooking is considered a malicious behavior that is performed by rootkits and may indicate that the host's kernel has been compromised. Hidden modules are marked as hidden symbol owners and indicate further malicious activity of an adversary.",
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
					EventName: "hooked_syscalls",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_syscalls",
							},
							Value: interface{}([]trace.HookedSymbolData{}),
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
			sig := SyscallTableHooking{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
