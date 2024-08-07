package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ProcFopsHooking struct {
	cb detect.SignatureHandler
}

var procFopsHookingMetadata = detect.SignatureMetadata{
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
}

func (sig *ProcFopsHooking) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *ProcFopsHooking) GetMetadata() (detect.SignatureMetadata, error) {
	return procFopsHookingMetadata, nil
}

func (sig *ProcFopsHooking) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "hooked_proc_fops", Origin: "host"},
	}, nil
}

func (sig *ProcFopsHooking) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "hooked_proc_fops":
		hookedSymbolSlice, err := helpers.GetTraceeHookedSymbolDataArgumentByName(eventObj, "hooked_fops_pointers")
		if err != nil {
			return err
		}

		if len(hookedSymbolSlice) > 0 {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data:        map[string]interface{}{"Hooked proc file operations": hookedSymbolSlice},
			})
		}
	}

	return nil
}

func (sig *ProcFopsHooking) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *ProcFopsHooking) Close() {}
