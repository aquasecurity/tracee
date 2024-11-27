package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eStackPivot struct {
	cb            detect.SignatureHandler
	falsePositive bool
}

func (sig *e2eStackPivot) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	return nil
}

func (sig *e2eStackPivot) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "STACK_PIVOT",
		EventName:   "STACK_PIVOT",
		Version:     "0.1.0",
		Name:        "Stack Pivot Test",
		Description: "Instrumentation events E2E Tests: Stack Pivot",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eStackPivot) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "stack_pivot"},
	}, nil
}

func (sig *e2eStackPivot) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "stack_pivot":
		syscall, err := helpers.ArgVal[string](eventObj.Args, "syscall")
		if err != nil {
			return err
		}
		vmaType, err := helpers.ArgVal[string](eventObj.Args, "vma_type")
		if err != nil {
			return err
		}

		// Make sure this is the exact event we're looking for
		if eventObj.ProcessName == "stack_pivot" && syscall == "exit_group" && vmaType == "heap" {
			// Make sure there was no false positive
			if !sig.falsePositive {
				m, _ := sig.GetMetadata()

				sig.cb(&detect.Finding{
					SigMetadata: m,
					Event:       event,
					Data:        map[string]interface{}{},
				})
			}
		} else {
			// False positive, mark it so that the test will fail
			sig.falsePositive = true
		}
	}

	return nil
}

func (sig *e2eStackPivot) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eStackPivot) Close() {}
