package golang

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
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

func (sig *antiDebugging) Init(cb detect.SignatureHandler) error {
	sig.cb = cb
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

func (sig *antiDebugging) OnEvent(e detect.Event) error {
	ee, ok := e.(trace.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}
	if ee.EventName != "ptrace" {
		return nil
	}
	request, err := helpers.GetTraceeArgumentByName(ee, "request")
	if err != nil {
		return err
	}
	requestString := request.Value.(string)
	if requestString != "PTRACE_TRACEME" {
		return nil
	}
	sig.cb(detect.Finding{
		SigMetadata: sig.metadata,
		Context:     ee,
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
