package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eProcessExecuteFailed struct {
	cb                    detect.SignatureHandler
	osInfo                *environment.OSInfo
	markUnsupportedKernel sync.Once
}

var e2eProcessExecuteFailedMetadata = detect.SignatureMetadata{
	ID:          "PROCESS_EXECUTE_FAILED",
	EventName:   "PROCESS_EXECUTE_FAILED",
	Version:     "0.1.0",
	Name:        "Process Execute Failed Test",
	Description: "Instrumentation events E2E Tests: Process Execute Failed",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eProcessExecuteFailed) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	var err error
	sig.osInfo, err = environment.GetOSInfo()
	if err != nil {
		return err
	}
	return nil
}

func (sig *e2eProcessExecuteFailed) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eProcessExecuteFailedMetadata, nil
}

func (sig *e2eProcessExecuteFailed) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "process_execute_failed"},
		{Source: "tracee", Name: "init_namespaces"},
	}, nil
}

func (sig *e2eProcessExecuteFailed) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "init_namespaces":
		// The event is not guaranteed to work for kernel version 5.7 or older, making the test
		// unreliable.
		// Ensure that the tests will pass (unless an error occur).
		var err error
		sig.markUnsupportedKernel.Do(
			func() {
				var comp environment.KernelVersionComparison
				comp, err = sig.osInfo.CompareOSBaseKernelRelease("5.7")
				if err != nil {
					return
				}
				if comp == environment.KernelVersionNewer { // < V5.8
					m, _ := sig.GetMetadata()

					sig.cb(&detect.Finding{
						SigMetadata: m,
						Event:       event,
					})
				}
			})
		if err != nil {
			return err
		}
	case "process_execute_failed":
		filePath, err := helpers.GetTraceeStringArgumentByName(eventObj, "path")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if !strings.HasSuffix(filePath, "test.sh") {
			return nil
		}

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eProcessExecuteFailed) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eProcessExecuteFailed) Close() {}
