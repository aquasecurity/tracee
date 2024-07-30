package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eSetFsPwd struct {
	cb          detect.SignatureHandler
	hasReadUser bool
	seen64Bit   bool
	seen32Bit   bool
}

func (sig *e2eSetFsPwd) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	// Find if this system has the bpf_probe_read_user_str helper.
	// If it doesn't we won't expect the unresolved path to contain anything
	ksyms, err := environment.NewKernelSymbolTable()
	if err != nil {
		return err
	}
	_, err = ksyms.GetSymbolByName("bpf_probe_read_user_str")
	if err != nil {
		sig.hasReadUser = false
	} else {
		sig.hasReadUser = true
	}

	sig.seen64Bit = false
	sig.seen32Bit = false

	return nil
}

func (sig *e2eSetFsPwd) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "SET_FS_PWD",
		EventName:   "SET_FS_PWD",
		Version:     "0.1.0",
		Name:        "set_fs_pwd Test",
		Description: "Instrumentation events E2E Tests: set_fs_pwd",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eSetFsPwd) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "set_fs_pwd"},
	}, nil
}

func (sig *e2eSetFsPwd) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "set_fs_pwd":
		unresolvedPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "unresolved_path")
		if sig.hasReadUser && err != nil {
			return err
		}

		resolvedPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "resolved_path")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if strings.HasSuffix(resolvedPath, "/test_dir_64") && (!sig.hasReadUser || strings.HasSuffix(unresolvedPath, "/test_link")) {
			sig.seen64Bit = true
		} else if strings.HasSuffix(resolvedPath, "/test_dir_32") && (!sig.hasReadUser || strings.HasSuffix(unresolvedPath, "/test_link")) {
			sig.seen32Bit = true
		} else {
			return nil
		}

		if sig.seen64Bit && sig.seen32Bit {
			m, _ := sig.GetMetadata()

			sig.cb(&detect.Finding{
				SigMetadata: m,
				Event:       event,
				Data:        map[string]interface{}{},
			})
		}
	}

	return nil
}

func (sig *e2eSetFsPwd) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eSetFsPwd) Close() {}
