package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIoIssueSqe struct {
	cb detect.SignatureHandler
}

func (sig *e2eIoIssueSqe) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIoIssueSqe) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "IO_ISSUE_SQE",
		EventName:   "IO_ISSUE_SQE",
		Version:     "0.1.0",
		Name:        "io_uring issue request Test",
		Description: "Instrumentation events E2E Tests: io_uring issue request",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eIoIssueSqe) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "io_issue_sqe"},
	}, nil
}

func (sig *e2eIoIssueSqe) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "io_issue_sqe":
		m, _ := sig.GetMetadata()
		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eIoIssueSqe) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIoIssueSqe) Close() {}
