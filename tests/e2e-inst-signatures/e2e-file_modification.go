package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eFileModification struct {
	cb detect.SignatureHandler
}

var e2eFileModificationMetadata = detect.SignatureMetadata{
	ID:          "FILE_MODIFICATION",
	EventName:   "FILE_MODIFICATION",
	Version:     "0.1.0",
	Name:        "File Modification Test",
	Description: "Instrumentation events E2E Tests: File Modification",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eFileModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eFileModification) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eFileModificationMetadata, nil
}

func (sig *e2eFileModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "file_modification"},
	}, nil
}

func (sig *e2eFileModification) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "file_modification":
		filePath, err := helpers.GetTraceeStringArgumentByName(eventObj, "file_path")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if !strings.HasSuffix(filePath, "/file_modification.txt") {
			return nil
		}

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eFileModification) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eFileModification) Close() {}
