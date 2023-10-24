package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eAccessRemoteVm struct {
	cb detect.SignatureHandler
}

func (sig *e2eAccessRemoteVm) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
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
	}, nil
}

func (sig *e2eAccessRemoteVm) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
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

		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eAccessRemoteVm) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eAccessRemoteVm) Close() {}
