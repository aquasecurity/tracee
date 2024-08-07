package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type DiskMount struct {
	cb     detect.SignatureHandler
	devDir string
}

var diskMountMetadata = detect.SignatureMetadata{
	ID:          "TRC-1014",
	Version:     "1",
	Name:        "Container device mount detected",
	EventName:   "disk_mount",
	Description: "Container device filesystem mount detected. A mount of a host device filesystem can be exploited by adversaries to perform container escape.",
	Properties: map[string]interface{}{
		"Severity":             3,
		"Category":             "privilege-escalation",
		"Technique":            "Escape to Host",
		"Kubernetes_Technique": "",
		"id":                   "attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665",
		"external_id":          "T1611",
	},
}

func (sig *DiskMount) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.devDir = "/dev/"
	return nil
}

func (sig *DiskMount) GetMetadata() (detect.SignatureMetadata, error) {
	return diskMountMetadata, nil
}

func (sig *DiskMount) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_sb_mount", Origin: "container"},
	}, nil
}

func (sig *DiskMount) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "security_sb_mount":
		if !eventObj.ContextFlags.ContainerStarted {
			return nil
		}

		deviceName, err := helpers.GetTraceeStringArgumentByName(eventObj, "dev_name")
		if err != nil {
			return nil
		}

		if strings.HasPrefix(deviceName, sig.devDir) {
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

func (sig *DiskMount) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *DiskMount) Close() {}
