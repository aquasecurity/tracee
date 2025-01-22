package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eBpfAttach struct {
	cb detect.SignatureHandler
}

func (sig *e2eBpfAttach) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eBpfAttach) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "BPF_ATTACH",
		EventName:   "BPF_ATTACH",
		Version:     "0.1.0",
		Name:        "Bpf Attach Test",
		Description: "Instrumentation events E2E Tests: Bpf Attach",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eBpfAttach) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "bpf_attach"},
	}, nil
}

func (sig *e2eBpfAttach) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "bpf_attach":
		symbolName, err := helpers.GetTraceeStringArgumentByName(eventObj, "symbol_name")
		if err != nil {
			return err
		}

		attachType, err := helpers.GetTraceeIntArgumentByName(eventObj, "attach_type")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if symbolName != "security_file_open" || attachType != int(parsers.BPFProgTypeKprobe) {
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

func (sig *e2eBpfAttach) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eBpfAttach) Close() {}
