package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type SchedDebugRecon struct {
	cb              detect.SignatureHandler
	schedDebugPaths []string
}

func (sig *SchedDebugRecon) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.schedDebugPaths = []string{"/proc/sched_debug", "/sys/kernel/debug/sched/debug"}
	return nil
}

func (sig *SchedDebugRecon) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1029",
		Version:     "1",
		Name:        "sched_debug CPU file was read",
		EventName:   "sched_debug_recon",
		Description: "The sched_debug file was read. This file contains information about your CPU and processes. Adversaries may read this file in order to gather that information for their use.",
		Properties: map[string]interface{}{
			"Severity":             1,
			"Category":             "discovery",
			"Technique":            "Container and Resource Discovery",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--0470e792-32f8-46b0-a351-652bc35e9336",
			"external_id":          "T1613",
		},
	}, nil
}

func (sig *SchedDebugRecon) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "container"},
	}, nil
}

func (sig *SchedDebugRecon) OnEvent(event protocol.Event) error {
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

		if helpers.IsFileRead(flags) {
			for _, schedDebugPath := range sig.schedDebugPaths {
				if pathname == schedDebugPath {
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

func (sig *SchedDebugRecon) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *SchedDebugRecon) Close() {}
