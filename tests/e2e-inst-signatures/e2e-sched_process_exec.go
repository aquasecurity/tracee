package main

import (
	"errors"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eSchedProcessExec struct {
	cb detect.SignatureHandler
}

func (sig *e2eSchedProcessExec) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eSchedProcessExec) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "SCHED_PROCESS_EXEC",
		EventName:   "SCHED_PROCESS_EXEC",
		Version:     "0.1.0",
		Name:        "sched_process_exec Test",
		Description: "Instrumentation events E2E Tests: sched_process_exec",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eSchedProcessExec) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exec"},
	}, nil
}

func (sig *e2eSchedProcessExec) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		// Validate prev_comm field is correctly populated after task rename
		// The test script renames the process to "e2e_rename_test" before exec
		prevComm, err := eventObj.GetStringArgumentByName("prev_comm")
		if err != nil {
			return err
		}

		// Check if this is our test case - prev_comm should be "e2e_rename_test"
		// and the executed process should be "true"
		if prevComm != "e2e_rename_test" {
			return nil
		}

		// Verify we're executing the expected program
		if eventObj.ProcessName != "true" {
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

func (sig *e2eSchedProcessExec) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eSchedProcessExec) Close() {}
