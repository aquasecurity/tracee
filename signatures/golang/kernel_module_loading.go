package main

import (
	"errors"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type KernelModuleLoading struct {
	cb detect.SignatureHandler
}

func (sig *KernelModuleLoading) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *KernelModuleLoading) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1017",
		Version:     "1",
		Name:        "Kernel module loading detected",
		EventName:   "kernel_module_loading",
		Description: "Loading of a kernel module was detected. Kernel modules are binaries meant to run in the kernel. Adversaries may try and load kernel modules to extend their capabilities and avoid detection by running in the kernel and not user space.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "persistence",
			"Technique":            "Kernel Modules and Extensions",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--a1b52199-c8c5-438a-9ded-656f1d0888c6",
			"external_id":          "T1547.006",
		},
	}, nil
}

func (sig *KernelModuleLoading) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "module_load", Origin: "*"},
	}, nil
}

func (sig *KernelModuleLoading) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("invalid event")
	}

	switch eventObj.EventName {
	case "module_load":
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

	return nil
}

func (sig *KernelModuleLoading) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *KernelModuleLoading) Close() {}
