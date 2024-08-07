package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eVfsWritev struct {
	cb detect.SignatureHandler
}

var e2eVfsWritevMetadata = detect.SignatureMetadata{
	ID:          "VFS_WRITEV",
	EventName:   "VFS_WRITEV",
	Version:     "0.1.0",
	Name:        "Vfs Writev Test",
	Description: "Instrumentation events E2E Tests: Vfs Writev",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eVfsWritev) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eVfsWritev) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eVfsWritevMetadata, nil
}

func (sig *e2eVfsWritev) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "vfs_writev"},
	}, nil
}

func (sig *e2eVfsWritev) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "vfs_writev":
		filePath, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if !strings.HasSuffix(filePath, "/vfs_writev.txt") {
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

func (sig *e2eVfsWritev) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eVfsWritev) Close() {}
