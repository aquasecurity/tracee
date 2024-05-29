package main

import (
	"fmt"
	"regexp"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ProcMemCodeInjection struct {
	cb                 detect.SignatureHandler
	procMemPathPattern string
	compiledRegex      *regexp.Regexp
}

func (sig *ProcMemCodeInjection) Init(ctx detect.SignatureContext) error {
	var err error
	sig.cb = ctx.Callback
	sig.procMemPathPattern = `/proc/(?:\d.+)/mem$`
	sig.compiledRegex, err = regexp.Compile(sig.procMemPathPattern)
	return err
}

func (sig *ProcMemCodeInjection) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1024",
		Version:     "1",
		Name:        "Code injection detected through /proc/<pid>/mem file",
		EventName:   "proc_mem_code_injection",
		Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "defense-evasion",
			"Technique":            "Proc Memory",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--d201d4cc-214d-4a74-a1ba-b3fa09fd4591",
			"external_id":          "T1055.009",
		},
	}, nil
}

func (sig *ProcMemCodeInjection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "*"},
	}, nil
}

func (sig *ProcMemCodeInjection) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "security_file_open":
		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		flags, err := helpers.GetTraceeIntArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if helpers.IsFileWrite(flags) && sig.compiledRegex.MatchString(pathname) {
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

func (sig *ProcMemCodeInjection) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *ProcMemCodeInjection) Close() {}
