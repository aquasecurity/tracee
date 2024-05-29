package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type PtraceCodeInjection struct {
	cb             detect.SignatureHandler
	ptracePokeText int
	ptracePokeData int
}

func (sig *PtraceCodeInjection) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.ptracePokeText = int(parsers.PTRACE_POKETEXT.Value())
	sig.ptracePokeData = int(parsers.PTRACE_POKEDATA.Value())
	return nil
}

func (sig *PtraceCodeInjection) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-103",
		Version:     "1",
		Name:        "Code injection detected using ptrace",
		EventName:   "ptrace_code_injection",
		Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "defense-evasion",
			"Technique":            "Ptrace System Calls",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--ea016b56-ae0e-47fe-967a-cc0ad51af67f",
			"external_id":          "T1055.008",
		},
	}, nil
}

func (sig *PtraceCodeInjection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace", Origin: "*"},
	}, nil
}

func (sig *PtraceCodeInjection) OnEvent(event protocol.Event) error {
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

		if requestArg == sig.ptracePokeText || requestArg == sig.ptracePokeData {
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

func (sig *PtraceCodeInjection) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *PtraceCodeInjection) Close() {}
