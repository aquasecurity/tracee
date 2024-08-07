package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eFtraceHook struct {
	cb detect.SignatureHandler
}

var e2eFtraceHookMetadata = detect.SignatureMetadata{
	ID:          "FTRACE_HOOK",
	EventName:   "FTRACE_HOOK",
	Version:     "0.1.0",
	Name:        "ftrace_hook Test",
	Description: "Instrumentation events E2E Tests: ftrace_hook",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eFtraceHook) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eFtraceHook) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eFtraceHookMetadata, nil
}

func (sig *e2eFtraceHook) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ftrace_hook"},
	}, nil
}

func (sig *e2eFtraceHook) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "ftrace_hook":
		symbolName, err := helpers.GetTraceeStringArgumentByName(eventObj, "symbol")
		if err != nil {
			return err
		}

		if symbolName != "commit_creds" {
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

func (sig *e2eFtraceHook) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eFtraceHook) Close() {}
