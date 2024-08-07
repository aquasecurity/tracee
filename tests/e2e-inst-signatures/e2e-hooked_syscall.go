package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eHookedSyscall struct {
	cb detect.SignatureHandler
}

var e2eHookedSyscallMetadata = detect.SignatureMetadata{
	ID:          "HOOKED_SYSCALL",
	EventName:   "HOOKED_SYSCALL",
	Version:     "0.1.0",
	Name:        "Hooked Syscall Test",
	Description: "Instrumentation events E2E Tests: Hooked Syscall",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eHookedSyscall) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eHookedSyscall) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eHookedSyscallMetadata, nil
}

func (sig *e2eHookedSyscall) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "hooked_syscall"},
	}, nil
}

func (sig *e2eHookedSyscall) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "hooked_syscall":
		syscall, err := helpers.GetTraceeStringArgumentByName(eventObj, "syscall")
		if err != nil {
			return err
		}
		owner, err := helpers.GetTraceeStringArgumentByName(eventObj, "owner")
		if err != nil {
			return err
		}

		if syscall == "uname" && owner == "hijack" {
			m, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				SigMetadata: m,
				Event:       event,
				Data:        map[string]interface{}{},
			})
		}
	}

	return nil
}

func (sig *e2eHookedSyscall) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eHookedSyscall) Close() {}
