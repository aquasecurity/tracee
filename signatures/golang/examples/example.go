package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// lint:ignore U1000 This is an example file with no real usage

// counter is a simple demo signature that counts towards a target
type counter struct {
	cb     detect.SignatureHandler
	target int
	count  int
}

// Init implements the Signature interface by resetting internal state
func (sig *counter) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.count = 0
	return nil
}

// GetMetadata implements the Signature interface by declaring information about the signature
func (sig *counter) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		Version: "0.1.0",
		Name:    "count to " + strconv.Itoa(sig.target),
	}, nil
}

// GetSelectedEvents implements the Signature interface by declaring which events this signature subscribes to
func (sig *counter) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{{
		Source: "tracee",
		// Name:   "execve",
	}}, nil
}

// OnEvent implements the Signature interface by handling each Event passed by the Engine. this is the business logic of the signature
func (sig *counter) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)

	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	if ee.ArgsNum > 0 && ee.Args[0].Name == "pathname" && strings.HasPrefix(ee.Args[0].Value.(string), "yo") {
		sig.count++
	}
	if sig.count == sig.target {
		m, _ := sig.GetMetadata()
		sig.cb(&detect.Finding{
			Data: map[string]interface{}{
				"count":    sig.count,
				"severity": "HIGH",
			},
			Event:       event,
			SigMetadata: m,
		})
		sig.count = 0
	}
	return nil
}

// OnSignal implements the Signature interface by handling lifecycle events of the signature
func (sig *counter) OnSignal(signal detect.Signal) error {
	source, sigcomplete := signal.(detect.SignalSourceComplete)
	if sigcomplete && source == "tracee" {
		sig.cb(&detect.Finding{
			Data: map[string]interface{}{
				"message": "done",
			},
		})
	}
	return nil
}
