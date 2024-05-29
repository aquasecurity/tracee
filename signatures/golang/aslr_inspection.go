package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type AslrInspection struct {
	cb       detect.SignatureHandler
	aslrPath string
}

func (sig *AslrInspection) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.aslrPath = "/proc/sys/kernel/randomize_va_space"
	return nil
}

func (sig *AslrInspection) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-109",
		Version:     "1",
		Name:        "ASLR inspection detected",
		EventName:   "aslr_inspection",
		Description: "The ASLR (address space layout randomization) configuration was inspected. ASLR is used by Linux to prevent memory vulnerabilities. An adversary may want to inspect and change the ASLR configuration in order to avoid detection.",
		Properties: map[string]interface{}{
			"Severity":             0,
			"Category":             "privilege-escalation",
			"Technique":            "Exploitation for Privilege Escalation",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
			"external_id":          "T1068",
		},
	}, nil
}

func (sig *AslrInspection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "*"},
	}, nil
}

func (sig *AslrInspection) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "security_file_open":
		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		flags, err := helpers.GetTraceeIntArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if pathname == sig.aslrPath && helpers.IsFileRead(flags) {
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

func (sig *AslrInspection) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *AslrInspection) Close() {}
