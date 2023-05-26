package golang

import (
	"fmt"

	libbpfgo "github.com/aquasecurity/libbpfgo/helpers"

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
	requestArg, err := helpers.GetTraceeIntArgumentByName(ee, "request")
	if err != nil {
		return err
	}

	if requestArg == int(libbpfgo.PTRACE_TRACEME.Value()) {
		metadata, err := sig.GetMetadata()
		if err != nil {
			return err
		}
		sig.cb(detect.Finding{
			SigMetadata: metadata,
			Event:       event,
			Data:        nil,
		})
	}
	return nil
}

func (sig *antiDebugging) OnSignal(_ detect.Signal) error {
	return nil
}

func (sig *antiDebugging) Close() {}
