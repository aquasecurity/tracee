package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type DroppedExecutable struct {
	cb detect.SignatureHandler
}

var droppedExecutableMetadata = detect.SignatureMetadata{
	ID:          "TRC-1022",
	Version:     "1",
	Name:        "New executable dropped",
	EventName:   "dropped_executable",
	Description: "An Executable file was dropped in the system during runtime. Container images are usually built with all binaries needed inside. A dropped binary may indicate that an adversary infiltrated your container.",
	Properties: map[string]interface{}{
		"Severity":             2,
		"Category":             "defense-evasion",
		"Technique":            "Masquerading",
		"Kubernetes_Technique": "",
		"id":                   "attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0",
		"external_id":          "T1036",
	},
}

func (sig *DroppedExecutable) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *DroppedExecutable) GetMetadata() (detect.SignatureMetadata, error) {
	return droppedExecutableMetadata, nil
}

func (sig *DroppedExecutable) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "magic_write", Origin: "container"},
	}, nil
}

func (sig *DroppedExecutable) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "magic_write":
		bytes, err := helpers.GetTraceeBytesSliceArgumentByName(eventObj, "bytes")
		if err != nil {
			return err
		}

		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		if helpers.IsElf(bytes) && !helpers.IsMemoryPath(pathname) {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data: map[string]interface{}{
					"path": pathname,
				},
			})
		}
	}
	return nil
}

func (sig *DroppedExecutable) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *DroppedExecutable) Close() {}
