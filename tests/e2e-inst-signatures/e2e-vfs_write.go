package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eVfsWrite struct {
	cb detect.SignatureHandler
}

var e2eVfsWriteMetadata = detect.SignatureMetadata{
	ID:          "VFS_WRITE",
	EventName:   "VFS_WRITE",
	Version:     "0.1.0",
	Name:        "Vfs Write Test",
	Description: "Instrumentation events E2E Tests: Vfs Write",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eVfsWrite) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eVfsWrite) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eVfsWriteMetadata, nil
}

func (sig *e2eVfsWrite) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "vfs_write"},
	}, nil
}

func (sig *e2eVfsWrite) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "vfs_write":
		filePath, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if !strings.HasSuffix(filePath, "/vfs_write.txt") {
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

func (sig *e2eVfsWrite) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eVfsWrite) Close() {}
