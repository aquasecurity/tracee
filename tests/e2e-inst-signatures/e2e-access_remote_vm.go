package main

import (
	"fmt"
	"sync"

	helpers2 "github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eAccessRemoteVm struct {
	cb                    detect.SignatureHandler
	osInfo                *helpers2.OSInfo
	markUnsupportedKernel sync.Once
}

func (sig *e2eAccessRemoteVm) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	var err error
	sig.osInfo, err = helpers2.GetOSInfo()
	if err != nil {
		return err
	}
	return nil
}

func (sig *e2eAccessRemoteVm) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "ACCESS_REMOTE_VM",
		EventName:   "ACCESS_REMOTE_VM",
		Version:     "0.1.0",
		Name:        "Access Remote VM Test",
		Description: "Instrumentation events E2E Tests: Access Remote VM",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eAccessRemoteVm) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "access_remote_vm"},
		{Source: "tracee", Name: "sched_process_exec"},
	}, nil
}

func (sig *e2eAccessRemoteVm) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		// The event does not support kernel versions 6.5 and newer, so pass the test if run in such
		// environment.
		var err error
		sig.markUnsupportedKernel.Do(
			func() {
				comp, err := sig.osInfo.CompareOSBaseKernelRelease("6.4")
				if err != nil {
					return
				}
				if comp == helpers2.KernelVersionOlder { // > V6.4
					m, _ := sig.GetMetadata()

					sig.cb(&detect.Finding{
						SigMetadata: m,
						Event:       event,
					})
				}
			})
		if err != nil {
			return err
		}

	case "access_remote_vm":
		remotePid, err := helpers.GetTraceeIntArgumentByName(eventObj, "remote_pid")
		if err != nil {
			return err
		}

		vmName, err := helpers.GetTraceeStringArgumentByName(eventObj, "mapped.path")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if remotePid != eventObj.HostParentProcessID || vmName != "[stack]" {
			return nil
		}

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
		})
	}

	return nil
}

func (sig *e2eAccessRemoteVm) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eAccessRemoteVm) Close() {}
