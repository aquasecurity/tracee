package main

import (
	"fmt"
	"regexp"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type DefaultLoaderModification struct {
	cb                   detect.SignatureHandler
	dynamicLoaderPattern string
	compiledRegex        *regexp.Regexp
}

func (sig *DefaultLoaderModification) Init(ctx detect.SignatureContext) error {
	var err error
	sig.cb = ctx.Callback
	sig.dynamicLoaderPattern = "^\\/(lib|usr\\/lib).*\\/ld.*\\.so[^\\/]*"
	sig.compiledRegex, err = regexp.Compile(sig.dynamicLoaderPattern)
	return err
}

func (sig *DefaultLoaderModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1012",
		Version:     "1",
		Name:        "Default dynamic loader modification detected",
		EventName:   "default_loader_mod",
		Description: "The default dynamic loader has been modified. The dynamic loader is an executable file loaded to process memory and run before the executable to load dynamic libraries to the process. An attacker might use this technique to hijack the execution context of each new process and bypass defenses.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "defense-evasion",
			"Technique":            "Hijack Execution Flow",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
			"external_id":          "T1574",
		},
	}, nil
}

func (sig *DefaultLoaderModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "*"},
		{Source: "tracee", Name: "security_inode_rename", Origin: "*"},
	}, nil
}

func (sig *DefaultLoaderModification) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	path := ""

	switch eventObj.EventName {
	case "security_file_open":
		flags, err := helpers.GetTraceeIntArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if helpers.IsFileWrite(flags) {
			pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
			if err != nil {
				return err
			}

			path = pathname
		}
	case "security_inode_rename":
		newPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "new_path")
		if err != nil {
			return err
		}

		path = newPath
	}

	if sig.compiledRegex.MatchString(path) {
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

	return nil
}

func (sig *DefaultLoaderModification) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *DefaultLoaderModification) Close() {}
