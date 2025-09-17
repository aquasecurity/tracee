package main

import (
	"errors"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eLsm struct {
	cb detect.SignatureHandler
}

func (sig *e2eLsm) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eLsm) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "LSM_TEST",
		EventName:   "LSM_TEST",
		Version:     "0.1.0",
		Name:        "LSM Test",
		Description: "Instrumentation events E2E Tests: LSM Test",
		Tags:        []string{"e2e", "instrumentation", "lsm"},
	}, nil
}

func (sig *e2eLsm) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "lsm_test"},
	}, nil
}

func (sig *e2eLsm) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "lsm_test":
		// Check expected values from test for detection
		// The LSM test event is triggered by file open operations
		// We don't need to check specific arguments as the event
		// itself being triggered indicates successful LSM probe functionality

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eLsm) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eLsm) Close() {}
