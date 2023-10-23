package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIoWrite struct {
	cb detect.SignatureHandler
}

func (sig *e2eIoWrite) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIoWrite) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "IO_WRITE",
		EventName:   "IO_WRITE",
		Version:     "0.1.0",
		Name:        "io_write Test",
		Description: "Instrumentation events E2E Tests: io_write",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eIoWrite) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "io_write"},
	}, nil
}

func (sig *e2eIoWrite) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "io_write":

		m, _ := sig.GetMetadata()

		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eIoWrite) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIoWrite) Close() {}
