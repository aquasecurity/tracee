package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/golang/internal/fingerprint"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type Fingerprint struct {
	cb                     detect.SignatureHandler
	processTreeDataSource  detect.DataSource
	processTreeFingerprint *fingerprint.ProcessTreeFingerprint
}

func (sig *Fingerprint) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	processTreeDataSource, ok := ctx.GetDataSource("tracee", "process_tree")
	if !ok {
		return fmt.Errorf("Data source tracee/process_tree is not registered")
	}

	// TODO: Create server to supply configuration, mode, etc.

	sig.processTreeDataSource = processTreeDataSource
	return nil
}

func (sig *Fingerprint) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "FGR-001",
		Version:     "1",
		Name:        "Fingerprint violation detected",
		EventName:   "fingerprint_violation",
		Description: "Behaviour was detected that violated a process' fingerprint. This indicates possible exploitation. ",
		Properties: map[string]interface{}{
			"Category": "fingerprint",
		},
	}, nil
}

func (sig *Fingerprint) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return append(
		(*fingerprint.FilesystemActivityEvents)[:],
		(*fingerprint.NetworkActivityEvents)[:]...,
	), nil
}

func (sig *Fingerprint) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("Invalid event - %v", event)
	}

	processFingeprint, ok := sig.processTreeFingerprint.GetOrCreateNodeForEvent(sig.processTreeDataSource, &eventObj)
	if !ok {
		return nil
	}

	processFingeprint.Update(&eventObj)
	return nil
}

// TODO: Look up what this is
func (sig *Fingerprint) OnSignal(s detect.Signal) error {
	return nil
}

// TODO: Implement
func (sig *Fingerprint) Close() {}
