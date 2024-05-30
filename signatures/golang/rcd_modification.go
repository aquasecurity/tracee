package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type RcdModification struct {
	cb         detect.SignatureHandler
	rcdFiles   []string
	rcdDirs    []string
	rcdCommand string
}

func (sig *RcdModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.rcdFiles = []string{"/etc/rc.local", "/etc/init.d/rc.local"}
	sig.rcdDirs = []string{"/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcs.d", "/etc/init.d", "/etc/rc.d/rc.local", "/etc/rc.d/init.d", "/etc/rc.d"}
	sig.rcdCommand = "update-rc.d"
	return nil
}

func (sig *RcdModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1026",
		Version:     "1",
		Name:        "Rcd modification detected",
		EventName:   "rcd_modification",
		Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "persistence",
			"Technique":            "RC Scripts",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
			"external_id":          "T1037.004",
		},
	}, nil
}

func (sig *RcdModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "*"},
		{Source: "tracee", Name: "security_inode_rename", Origin: "*"},
		{Source: "tracee", Name: "sched_process_exec", Origin: "*"},
	}, nil
}

func (sig *RcdModification) OnEvent(event protocol.Event) error {
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

		if helpers.IsFileWrite(flags) {
			return sig.checkFileOrDir(event, pathname)
		}
	case "security_inode_rename":
		newPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "new_path")
		if err != nil {
			return err
		}

		return sig.checkFileOrDir(event, newPath)
	case "sched_process_exec":
		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}
		basename := path.Base(pathname)

		if basename == sig.rcdCommand {
			return sig.match(event)
		}
	}

	return nil
}

func (sig *RcdModification) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *RcdModification) Close() {}

func (sig *RcdModification) checkFileOrDir(event protocol.Event, pathname string) error {
	for _, rcdFile := range sig.rcdFiles {
		if pathname == rcdFile {
			return sig.match(event)
		}
	}

	for _, rcdDir := range sig.rcdDirs {
		if strings.HasPrefix(pathname, rcdDir) {
			return sig.match(event)
		}
	}

	return nil
}

func (sig *RcdModification) match(event protocol.Event) error {
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
