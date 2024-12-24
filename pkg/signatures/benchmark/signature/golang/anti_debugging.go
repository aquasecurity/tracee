package golang

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type antiDebugging struct {
	cb       detect.SignatureHandler
	metadata detect.SignatureMetadata
}

func NewAntiDebuggingSignature() (detect.Signature, error) {
	return &antiDebugging{
		metadata: detect.SignatureMetadata{
			Name:        "Anti-Debugging",
			Description: "Process uses anti-debugging technique to block debugger",
			Tags:        []string{"linux", "container"},
			Properties: map[string]interface{}{
				"Severity":     3,
				"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
			},
		},
	}, nil
}

func (sig *antiDebugging) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *antiDebugging) GetMetadata() (detect.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *antiDebugging) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
	}, nil
}

func (sig *antiDebugging) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)

	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	if ee.EventName != "ptrace" {
		return nil
	}
	request, err := helpers.GetTraceeArgumentByName(ee, "request", helpers.GetArgOps{DefaultArgs: false})
	if err != nil {
		return err
	}
	requestString, ok := request.Value.(string)
	if !ok {
		return fmt.Errorf("failed to cast request's value")
	}
	if requestString != "PTRACE_TRACEME" {
		return nil
	}
	sig.cb(&detect.Finding{
		SigMetadata: sig.metadata,
		Event:       event,
		Data: map[string]interface{}{
			"ptrace request": requestString,
		},
	})
	return nil
}

func (sig *antiDebugging) OnSignal(_ detect.Signal) error {
	return nil
}

func (sig *antiDebugging) Close() {}
