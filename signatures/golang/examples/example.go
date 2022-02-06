package main

import (
	"fmt"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	"strconv"
	"strings"
)

// counter is a simple demo signature that counts towards a target
type counter struct {
	cb     detect.SignatureHandler
	target int
	count  int
}

// Init implements the Signature interface by resetting internal state
func (sig *counter) Init(cb detect.SignatureHandler) error {
	sig.cb = cb
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
		//Name:   "execve",
	}}, nil
}

// OnEvent implements the Signature interface by handling each Event passed by the Engine. this is the business logic of the signature
func (sig *counter) OnEvent(e detect.Event) error {
	ee, ok := e.(trace.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	if ee.ArgsNum > 0 && ee.Args[0].Name == "pathname" && strings.HasPrefix(ee.Args[0].Value.(string), "yo") {
		sig.count++
	}
	if sig.count == sig.target {
		m, _ := sig.GetMetadata()
		sig.cb(detect.Finding{
			Data: map[string]interface{}{
				"count":    sig.count,
				"severity": "HIGH",
			},
			Context:     e,
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
		sig.cb(detect.Finding{
			Data: map[string]interface{}{
				"message": "done",
			},
		})
	}
	return nil
}
