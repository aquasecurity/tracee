package main

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// ExportedSignatures fulfills the goplugins contract required by the rule-engine
// this is a list of signatures that this plugin exports
var ExportedSignatures []types.Signature = []types.Signature{
	&counter{target: 2},
	&counter{target: 3},
}

// counter is a simple demo signature that counts towards a target
type counter struct {
	cb     types.SignatureHandler
	target int
	count  int
}

// Init implements the Signature interface by resetting internal state
func (sig *counter) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	sig.count = 0
	return nil
}

// GetMetadata implements the Signature interface by declaring information about the signature
func (sig *counter) GetMetadata() types.SignatureMetadata {
	return types.SignatureMetadata{
		Name: "count to " + strconv.Itoa(sig.target),
	}
}

// GetSelectedEvents implements the Signature interface by declaring which events this signature subscribes to
func (sig *counter) GetSelectedEvents() []types.SignatureEventSelector {
	return []types.SignatureEventSelector{{
		Source: "tracee",
		//Name:   "execve",
	}}
}

// OnEvent implements the Signature interface by handling each Event passed by the Engine. this is the business logic of the signature
func (sig *counter) OnEvent(e types.Event) error {
	ee, ok := e.(types.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	if ee.ArgsNum > 0 && ee.Args[0].Name == "pathname" && filepath.Base(ee.Args[0].Value.(string)) == "yo" {
		sig.count++
	}
	if sig.count == sig.target {
		sig.cb(types.Finding{
			Data: []types.FindingData{{
				Type: "count",
				Properties: map[string]interface{}{
					"count":    sig.count,
					"severity": "HIGH",
				}}},
			Context:   e,
			Signature: sig,
		})
		sig.count = 0
	}
	return nil
}

// OnSignal implements the Signature interface by handling lifecycle events of the signature
func (sig *counter) OnSignal(signal types.Signal) error {
	source, sigcomplete := signal.(types.SignalSourceComplete)
	if sigcomplete && source == "tracee" {
		sig.cb(types.Finding{
			Data: []types.FindingData{{
				Type: "message",
				Properties: map[string]interface{}{
					"message": "done",
				},
			}}})
	}
	return nil
}
