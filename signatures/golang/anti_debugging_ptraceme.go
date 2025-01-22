package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type AntiDebuggingPtraceme struct {
	cb            detect.SignatureHandler
	ptraceTraceMe int
}

func (sig *AntiDebuggingPtraceme) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.ptraceTraceMe = int(parsers.PTRACE_TRACEME.Value())
	return nil
}

func (sig *AntiDebuggingPtraceme) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-102",
		Version:     "1",
		Name:        "Anti-Debugging detected",
		EventName:   "anti_debugging",
		Description: "A process used anti-debugging techniques to block a debugger. Malware use anti-debugging to stay invisible and inhibit analysis of their behavior.",
		Properties: map[string]interface{}{
			"Severity":             1,
			"Category":             "defense-evasion",
			"Technique":            "Debugger Evasion",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391",
			"external_id":          "T1622",
		},
	}, nil
}

func (sig *AntiDebuggingPtraceme) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace", Origin: "*"},
	}, nil
}

func (sig *AntiDebuggingPtraceme) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "ptrace":
		requestArg, err := helpers.GetTraceeIntArgumentByName(eventObj, "request")
		if err != nil {
			return err
		}

		if requestArg == sig.ptraceTraceMe {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data:        nil,
			})
		}
	}

	return nil
}

func (sig *AntiDebuggingPtraceme) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *AntiDebuggingPtraceme) Close() {}
