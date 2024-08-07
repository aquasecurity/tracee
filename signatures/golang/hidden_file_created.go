package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type HiddenFileCreated struct {
	cb                detect.SignatureHandler
	hiddenPathPattern string
}

var hiddenFileCreatedMetadata = detect.SignatureMetadata{
	ID:          "TRC-1015",
	Version:     "1",
	Name:        "Hidden executable creation detected",
	EventName:   "hidden_file_created",
	Description: "A hidden executable (ELF file) was created on disk. This activity could be legitimate; however, it could indicate that an adversary is trying to avoid detection by hiding their programs.",
	Properties: map[string]interface{}{
		"Severity":             2,
		"Category":             "defense-evasion",
		"Technique":            "Hidden Files and Directories",
		"Kubernetes_Technique": "",
		"id":                   "attack-pattern--ec8fc7e2-b356-455c-8db5-2e37be158e7d",
		"external_id":          "T1564.001",
	},
}

func (sig *HiddenFileCreated) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.hiddenPathPattern = "/."
	return nil
}

func (sig *HiddenFileCreated) GetMetadata() (detect.SignatureMetadata, error) {
	return hiddenFileCreatedMetadata, nil
}

func (sig *HiddenFileCreated) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "magic_write", Origin: "*"},
	}, nil
}

func (sig *HiddenFileCreated) OnEvent(event protocol.Event) error {
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

		if helpers.IsElf(bytes) && strings.Contains(pathname, sig.hiddenPathPattern) {
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

func (sig *HiddenFileCreated) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *HiddenFileCreated) Close() {}
