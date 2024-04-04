package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eCheckSyscallSource struct {
	cb           detect.SignatureHandler
	foundStack   bool
	foundHeap    bool
	foundAnonVma bool
}

func (sig *e2eCheckSyscallSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eCheckSyscallSource) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "CHECK_SYSCALL_SOURCE",
		EventName:   "CHECK_SYSCALL_SOURCE",
		Version:     "0.1.0",
		Name:        "Check Syscall Source Test",
		Description: "Instrumentation events E2E Tests: Check Syscall Source",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eCheckSyscallSource) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "check_syscall_source"},
	}, nil
}

func (sig *e2eCheckSyscallSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "check_syscall_source":
		syscall, err := helpers.GetTraceeStringArgumentByName(eventObj, "syscall")
		if err != nil {
			return err
		}
		isStack, err := helpers.ArgVal[bool](eventObj.Args, "is_stack")
		if err != nil {
			return err
		}
		isHeap, err := helpers.ArgVal[bool](eventObj.Args, "is_heap")
		if err != nil {
			return err
		}
		isAnonVma, err := helpers.ArgVal[bool](eventObj.Args, "is_anon_vma")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if syscall != "exit" {
			return nil
		}

		if isStack {
			sig.foundStack = true
		} else if isHeap {
			sig.foundHeap = true
		} else if isAnonVma {
			sig.foundAnonVma = true
		} else {
			return nil
		}

		if !sig.foundStack || !sig.foundHeap || !sig.foundAnonVma {
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

func (sig *e2eCheckSyscallSource) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eCheckSyscallSource) Close() {}
