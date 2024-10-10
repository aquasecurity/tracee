package main

import (
	"fmt"

	libbpfgo "github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eCheckSyscallSource struct {
	cb           detect.SignatureHandler
	hasMapleTree bool
	foundStack   bool
	foundHeap    bool
	foundAnonVma bool
}

func (sig *e2eCheckSyscallSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	// Find if this system uses maple trees to manage VMAs.
	// If so we don't expect any check_syscall_source event to be submitted.
	ksyms, err := libbpfgo.NewKernelSymbolsMap()
	if err != nil {
		return err
	}
	_, err = ksyms.GetSymbolByName("system", "mt_find")
	if err != nil {
		sig.hasMapleTree = false
	} else {
		sig.hasMapleTree = true
	}

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
		{Source: "tracee", Name: "init_namespaces"}, // This event always happens so we can pass the test on unsupported kernels
	}, nil
}

func (sig *e2eCheckSyscallSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "init_namespaces":
		// If the system uses maple trees we won't get any check_syscall_source events, pass the test
		if sig.hasMapleTree {
			m, _ := sig.GetMetadata()

			sig.cb(&detect.Finding{
				SigMetadata: m,
				Event:       event,
				Data:        map[string]interface{}{},
			})

			return nil
		}
	case "check_syscall_source":
		syscall, err := helpers.GetTraceeIntArgumentByName(eventObj, "syscall")
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

		if syscall != int(events.Exit) {
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
