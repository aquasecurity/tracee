package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type SyscallTableHooking struct {
	cb detect.SignatureHandler
}

var syscallTableHookingMetadata = detect.SignatureMetadata{
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
}

func (sig *SyscallTableHooking) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *SyscallTableHooking) GetMetadata() (detect.SignatureMetadata, error) {
	return syscallTableHookingMetadata, nil
}

func (sig *SyscallTableHooking) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "hooked_syscall", Origin: "*"},
	}, nil
}

func (sig *SyscallTableHooking) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "hooked_syscall":
		metadata, err := sig.GetMetadata()
		if err != nil {
			return err
		}
		sig.cb(&detect.Finding{
			SigMetadata: metadata,
			Event:       event,
		})
	}

	return nil
}

func (sig *SyscallTableHooking) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *SyscallTableHooking) Close() {}
