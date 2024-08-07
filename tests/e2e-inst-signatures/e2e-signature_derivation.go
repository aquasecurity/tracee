package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eSignatureDerivation struct {
	cb detect.SignatureHandler
}

var e2eSignatureDerivationMetadata = detect.SignatureMetadata{
	ID:          "SIGNATURE_DERIVATION",
	EventName:   "SIGNATURE_DERIVATION",
	Version:     "0.1.0",
	Name:        "Signature Derivation Test",
	Description: "Instrumentation events E2E Tests: Signature Derivation",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eSignatureDerivation) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eSignatureDerivation) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eSignatureDerivationMetadata, nil
}

func (sig *e2eSignatureDerivation) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "FILE_MODIFICATION"},
	}, nil
}

func (sig *e2eSignatureDerivation) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "FILE_MODIFICATION":
		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eSignatureDerivation) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eSignatureDerivation) Close() {}
