package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eSuspiciousSyscallSource struct {
	cb               detect.SignatureHandler
	foundMainStack   bool
	foundHeap        bool
	foundAnonVma     bool
	foundThreadStack bool
}

func (sig *e2eSuspiciousSyscallSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	return nil
}

func (sig *e2eSuspiciousSyscallSource) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "SUSPICIOUS_SYSCALL_SOURCE",
		EventName:   "SUSPICIOUS_SYSCALL_SOURCE",
		Version:     "0.1.0",
		Name:        "Suspicious Syscall Source Test",
		Description: "Instrumentation events E2E Tests: Suspicious Syscall Source",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eSuspiciousSyscallSource) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "suspicious_syscall_source"},
	}, nil
}

func (sig *e2eSuspiciousSyscallSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "suspicious_syscall_source":
		syscall, err := helpers.ArgVal[string](eventObj.Args, "syscall")
		if err != nil {
			return err
		}
		vmaType, err := helpers.ArgVal[string](eventObj.Args, "vma_type")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if syscall != "exit" {
			return nil
		}

		if vmaType == "main stack" {
			sig.foundMainStack = true
		} else if vmaType == "heap" {
			sig.foundHeap = true
		} else if vmaType == "anonymous" {
			sig.foundAnonVma = true
		} else if vmaType == "thread stack" {
			sig.foundThreadStack = true
		} else {
			return nil
		}

		if !sig.foundMainStack || !sig.foundHeap || !sig.foundAnonVma || !sig.foundThreadStack {
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

func (sig *e2eSuspiciousSyscallSource) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eSuspiciousSyscallSource) Close() {}
