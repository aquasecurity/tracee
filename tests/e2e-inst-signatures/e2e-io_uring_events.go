package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIoUring struct {
	cb            detect.SignatureHandler
	ioIssueSqe    bool
	ioWrite       bool
	ioUringCreate bool
}

func (sig *e2eIoUring) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIoUring) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "IO_URING_EVENTS",
		EventName:   "IO_URING_EVENTS",
		Version:     "0.1.0",
		Name:        "io_uring events Test",
		Description: "Instrumentation events E2E Tests: io_uring events",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eIoUring) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "io_write"},
		{Source: "tracee", Name: "io_issue_sqe"},
		{Source: "tracee", Name: "io_uring_create"},
	}, nil
}

func (sig *e2eIoUring) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "io_write":
		err := sig.handleIoWrite(event)
		if err != nil {
			return err
		}
		sig.ioWrite = true
	case "io_issue_sqe":
		err := sig.handleIoIssueSqe(event)
		if err != nil {
			return err
		}
		sig.ioIssueSqe = true
	case "io_uring_create":
		err := sig.handleIoUringCreate(event)
		if err != nil {
			return err
		}
		sig.ioUringCreate = true
	}

	if sig.ioWrite && sig.ioIssueSqe && sig.ioUringCreate {
		m, _ := sig.GetMetadata()
		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eIoUring) handleIoWrite(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	// do some validations...

	return nil
}

func (sig *e2eIoUring) handleIoIssueSqe(event protocol.Event) error {

	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	// do some validations...
	return nil
}

func (sig *e2eIoUring) handleIoUringCreate(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	// do some validations...

	return nil
}

func (sig *e2eIoUring) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIoUring) Close() {}
