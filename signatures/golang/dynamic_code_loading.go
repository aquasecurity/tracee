package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type DynamicCodeLoading struct {
	cb        detect.SignatureHandler
	alertType trace.MemProtAlert
}

func (sig *DynamicCodeLoading) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.alertType = trace.ProtAlertMprotectWXToX
	return nil
}

func (sig *DynamicCodeLoading) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-104",
		Version:     "1",
		Name:        "Dynamic code loading detected",
		EventName:   "dynamic_code_loading",
		Description: "Possible dynamic code loading was detected as the binary's memory is both writable and executable. Writing to an executable allocated memory region could be a technique used by adversaries to run code undetected and without dropping executables.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "defense-evasion",
			"Technique":            "Software Packing",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
			"external_id":          "T1027.002",
		},
	}, nil
}

func (sig *DynamicCodeLoading) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "mem_prot_alert", Origin: "*"},
	}, nil
}

func (sig *DynamicCodeLoading) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "mem_prot_alert":
		alert, err := helpers.GetTraceeUintArgumentByName(eventObj, "alert")
		if err != nil {
			return err
		}
		memProtAlert := trace.MemProtAlert(alert)

		if memProtAlert == sig.alertType {
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

func (sig *DynamicCodeLoading) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *DynamicCodeLoading) Close() {}
