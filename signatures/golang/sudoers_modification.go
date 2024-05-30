package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type SudoersModification struct {
	cb           detect.SignatureHandler
	sudoersFiles []string
	sudoersDirs  []string
}

func (sig *SudoersModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.sudoersFiles = []string{"/etc/sudoers", "/private/etc/sudoers"}
	sig.sudoersDirs = []string{"/etc/sudoers.d/", "/private/etc/sudoers.d/"}
	return nil
}

func (sig *SudoersModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1028",
		Version:     "1",
		Name:        "Sudoers file modification detected",
		EventName:   "sudoers_modification",
		Description: "The sudoers file was modified. The sudoers file is a configuration file which controls the permissions and options of the sudo feature. Adversaries may alter the sudoers file to elevate privileges, execute commands as other users or spawn processes with higher privileges.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "privilege-escalation",
			"Technique":            "Sudo and Sudo Caching",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0",
			"external_id":          "T1548.003",
		},
	}, nil
}

func (sig *SudoersModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "*"},
		{Source: "tracee", Name: "security_inode_rename", Origin: "*"},
	}, nil
}

func (sig *SudoersModification) OnEvent(event protocol.Event) error {
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

	for _, sudoersFile := range sig.sudoersFiles {
		if path == sudoersFile {
			return sig.match(event)
		}
	}

	for _, sudoersDir := range sig.sudoersDirs {
		if strings.HasPrefix(path, sudoersDir) {
			return sig.match(event)
		}
	}

	return nil
}

func (sig *SudoersModification) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *SudoersModification) Close() {}

func (sig *SudoersModification) match(event protocol.Event) error {
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	sig.cb(&detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data:        nil,
	})

	return nil
}
