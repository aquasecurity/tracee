package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type SystemRequestKeyConfigModification struct {
	cb         detect.SignatureHandler
	sysrqPaths []string
}

func (sig *SystemRequestKeyConfigModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.sysrqPaths = []string{"/proc/sys/kernel/sysrq", "/proc/sysrq-trigger"}
	return nil
}

func (sig *SystemRequestKeyConfigModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1031",
		Version:     "1",
		Name:        "System request key configuration modification",
		EventName:   "system_request_key_mod",
		Description: "An attempt to modify and activate the System Request Key configuration file was detected. The system request key allows immediate input to the kernel through simple key combinations. Adversaries may use this feature to immediately shut down or restart a system. With read access to kernel logs, host related information such as listing tasks and CPU registers may be disclosed and could be used for container escape.",
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

func (sig *SystemRequestKeyConfigModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "container"},
	}, nil
}

func (sig *SystemRequestKeyConfigModification) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "security_file_open":
		flags, err := helpers.GetTraceeIntArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if helpers.IsFileWrite(flags) {
			pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
			if err != nil {
				return err
			}

			for _, sysrqPath := range sig.sysrqPaths {
				if pathname == sysrqPath {
					metadata, err := sig.GetMetadata()
					if err != nil {
						return err
					}
					sig.cb(&detect.Finding{
						SigMetadata: metadata,
						Event:       event,
						Data:        nil,
					})

					return nil
				}
			}
		}
	}

	return nil
}

func (sig *SystemRequestKeyConfigModification) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *SystemRequestKeyConfigModification) Close() {}
