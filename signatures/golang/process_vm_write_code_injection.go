package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ProcessVmWriteCodeInjection struct {
	cb detect.SignatureHandler
}

var processVmWriteCodeInjectionMetadata = detect.SignatureMetadata{
	ID:          "TRC-1025",
	Version:     "1",
	Name:        "Code injection detected using process_vm_writev syscall",
	EventName:   "process_vm_write_inject",
	Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
	Properties: map[string]interface{}{
		"Severity":             3,
		"Category":             "defense-evasion",
		"Technique":            "Process Injection",
		"Kubernetes_Technique": "",
		"id":                   "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
		"external_id":          "T1055",
	},
}

func (sig *ProcessVmWriteCodeInjection) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	return nil
}

func (sig *ProcessVmWriteCodeInjection) GetMetadata() (detect.SignatureMetadata, error) {
	return processVmWriteCodeInjectionMetadata, nil
}

func (sig *ProcessVmWriteCodeInjection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "process_vm_writev", Origin: "*"},
	}, nil
}

func (sig *ProcessVmWriteCodeInjection) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "process_vm_writev":
		dstPid, err := helpers.GetTraceeIntArgumentByName(eventObj, "pid")
		if err != nil {
			return err
		}

		if eventObj.ProcessID != dstPid {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data:        nil,
			})
		}
	}

	return nil
}

func (sig *ProcessVmWriteCodeInjection) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *ProcessVmWriteCodeInjection) Close() {}
