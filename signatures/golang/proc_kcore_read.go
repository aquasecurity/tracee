package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ProcKcoreRead struct {
	cb        detect.SignatureHandler
	kcorePath string
}

func (sig *ProcKcoreRead) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.kcorePath = "/proc/kcore"
	return nil
}

func (sig *ProcKcoreRead) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1021",
		Version:     "1",
		Name:        "Kcore memory file read",
		EventName:   "proc_kcore_read",
		Description: "An attempt to read /proc/kcore file was detected. KCore provides a full dump of the physical memory of the system in the core file format. Adversaries may read this file to get all of the host memory and use this information for container escape.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "privilege-escalation",
			"Technique":            "Escape to Host",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665",
			"external_id":          "T1611",
		},
	}, nil
}

func (sig *ProcKcoreRead) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "container"},
	}, nil
}

func (sig *ProcKcoreRead) OnEvent(event protocol.Event) error {
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

		if strings.HasSuffix(pathname, sig.kcorePath) && helpers.IsFileRead(flags) {
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

func (sig *ProcKcoreRead) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *ProcKcoreRead) Close() {}
