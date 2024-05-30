package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type CorePatternModification struct {
	cb          detect.SignatureHandler
	corePattern string
}

func (sig *CorePatternModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.corePattern = "/proc/sys/kernel/core_pattern"
	return nil
}

func (sig *CorePatternModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1011",
		Version:     "1",
		Name:        "Core dumps configuration file modification detected",
		EventName:   "core_pattern_modification",
		Description: "Modification of the core dump configuration file (core_pattern) detected. Core dumps are usually written to disk when a program crashes. Certain modifications enable container escaping through the kernel core_pattern feature.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "privilege-escalation",
			"Technique":            "Escape to Host",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665",
			"external_id":          "T1611",
		},
	}, nil
}

func (sig *CorePatternModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "container"},
	}, nil
}

func (sig *CorePatternModification) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
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

		if strings.HasSuffix(pathname, sig.corePattern) && helpers.IsFileWrite(flags) {
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

func (sig *CorePatternModification) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *CorePatternModification) Close() {}
