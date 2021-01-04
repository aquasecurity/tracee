package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type antiDebuggingPtraceme struct {
	cb types.SignatureHandler
}

func (sig *antiDebuggingPtraceme) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	return nil
}

func (sig *antiDebuggingPtraceme) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		Name:        "detect self debugging using PTRACE_ME",
		Description: "Process uses anti-debugging technique to block debugger",
		Tags:        []string{"linux", "container"},
		Properties: map[string]interface{}{
			"Severity":     3,
			"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
		},
	}, nil
}

func (sig *antiDebuggingPtraceme) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{{
		Source: "tracee",
		Name:   "ptrace",
	}}, nil
}

func (sig *antiDebuggingPtraceme) OnEvent(e types.Event) error {
	// event example:
	// { "eventName": "ptrace", "argsNum": 1, "args": [{"name": "request", "value": "PTRACE_TRACEME" }]}
	ee, ok := e.(types.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}
	if ee.EventName != "ptrace" {
		return fmt.Errorf("invalid event")
	}
	request, err := GetTraceeArgumentByName(ee, "request")
	if err != nil {
		return err
	}
	if request.Value.(string) == "PTRACE_TRACEME" {
		sig.cb(types.Finding{Context: e, Signature: sig})
	}
	return nil
}

func (sig *antiDebuggingPtraceme) OnSignal(s types.Signal) error {
	return nil
}
