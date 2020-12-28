package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

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
func (sig *counter) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		Name: "count to " + strconv.Itoa(sig.target),
	}, nil
}

// GetSelectedEvents implements the Signature interface by declaring which events this signature subscribes to
func (sig *counter) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{{
		Source: "tracee",
		//Name:   "execve",
	}}, nil
}

// OnEvent implements the Signature interface by handling each Event passed by the Engine. this is the business logic of the signature
func (sig *counter) OnEvent(e types.Event) error {
	ee, ok := e.(types.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	if ee.ArgsNum > 0 && ee.Args[0].Name == "pathname" && strings.HasPrefix(ee.Args[0].Value.(string), "yo") {
		sig.count++
	}
	if sig.count == sig.target {
		sig.cb(types.Finding{
			Data: map[string]interface{}{
				"count":    sig.count,
				"severity": "HIGH",
			},
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
			Data: map[string]interface{}{
				"message": "done",
			},
		})
	}
	return nil
}
