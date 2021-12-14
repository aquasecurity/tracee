package golang

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type antiDebugging struct {
	cb       types.SignatureHandler
	metadata types.SignatureMetadata
}

func NewAntiDebuggingSignature() (types.Signature, error) {
	return &antiDebugging{
		metadata: types.SignatureMetadata{
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

func (sig *antiDebugging) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	return nil
}

func (sig *antiDebugging) GetMetadata() (types.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *antiDebugging) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
	}, nil
}

func (sig *antiDebugging) OnEvent(e types.Event) error {
	ee, ok := e.(external.Event)
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
	sig.cb(types.Finding{
		SigMetadata: sig.metadata,
		Context:     ee,
		Data: map[string]interface{}{
			"ptrace request": requestString,
		},
	})
	return nil
}

func (sig *antiDebugging) OnSignal(_ types.Signal) error {
	return nil
}

func (sig *antiDebugging) Close() {}
