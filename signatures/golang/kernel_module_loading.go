package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type KernelModuleLoading struct {
	cb detect.SignatureHandler
}

var kernelModuleLoadingMetadata = detect.SignatureMetadata{
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
}

func (sig *KernelModuleLoading) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *KernelModuleLoading) GetMetadata() (detect.SignatureMetadata, error) {
	return kernelModuleLoadingMetadata, nil
}

func (sig *KernelModuleLoading) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "init_module", Origin: "*"},
		{Source: "tracee", Name: "security_kernel_read_file", Origin: "*"},
	}, nil
}

func (sig *KernelModuleLoading) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "init_module":
		metadata, err := sig.GetMetadata()
		if err != nil {
			return err
		}
		sig.cb(&detect.Finding{
			SigMetadata: metadata,
			Event:       event,
			Data:        nil,
		})
	case "security_kernel_read_file":
		loadedType, err := helpers.GetTraceeStringArgumentByName(eventObj, "type")
		if err != nil {
			return err
		}

		if loadedType == "kernel-module" {
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

func (sig *KernelModuleLoading) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *KernelModuleLoading) Close() {}
