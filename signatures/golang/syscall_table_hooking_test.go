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
					EventName: "hooked_syscall",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "hooked_syscall",
							},
							Value: map[string]interface{}{
								"syscall_name":         "kill",
								"hooked.address":       "0xdeadbeef",
								"hooked.function_name": "hooked_kill",
								"hooked.owner":         "rootkit",
							},
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-1030": {
					Data: nil,
					Event: trace.Event{
						EventName: "hooked_syscall",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "hooked_syscall",
								},
								Value: map[string]interface{}{
									"syscall_name":         "kill",
									"hooked.address":       "0xdeadbeef",
									"hooked.function_name": "hooked_kill",
									"hooked.owner":         "rootkit",
								},
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
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

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
