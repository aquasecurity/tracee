package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eWritableDatasourceSig struct {
	cb       detect.SignatureHandler
	writable detect.DataSource
}

var e2eWritableDatasourceSigMetadata = detect.SignatureMetadata{
	ID:          "WRITABLE_DATA_SOURCE",
	EventName:   "WRITABLE_DATA_SOURCE",
	Version:     "0.1.0",
	Name:        "Writable Data Source Test",
	Description: "Instrumentation events E2E Tests: Writable Data Source Test",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eWritableDatasourceSig) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	writable, ok := ctx.GetDataSource("e2e_inst", "demo")
	if !ok {
		return fmt.Errorf("containers data source not registered")
	}
	if writable.Version() > 1 {
		return fmt.Errorf("containers data source version not supported, please update this signature")
	}
	sig.writable = writable
	return nil
}

func (sig *e2eWritableDatasourceSig) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eWritableDatasourceSigMetadata, nil
}

func (sig *e2eWritableDatasourceSig) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exit"},
	}, nil
}

func (sig *e2eWritableDatasourceSig) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exit":
		if eventObj.ProcessName != "ds_writer" {
			return nil
		}

		container, err := sig.writable.Get("bruh")
		if err != nil {
			return fmt.Errorf("failed to query key \"bruh\" in data source: %v", err)
		}

		data, ok := container["value"].(string)
		if !ok {
			return fmt.Errorf("failed to unwrap value from writable data")
		}

		if data != "moment" {
			return fmt.Errorf("value written in data source not expected (%s)", data)
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

func (sig *e2eWritableDatasourceSig) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eWritableDatasourceSig) Close() {}
