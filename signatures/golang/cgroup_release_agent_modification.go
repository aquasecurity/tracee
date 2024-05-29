package main

import (
	"fmt"
	"path"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type CgroupReleaseAgentModification struct {
	cb               detect.SignatureHandler
	releaseAgentName string
}

func (sig *CgroupReleaseAgentModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.releaseAgentName = "release_agent"
	return nil
}

func (sig *CgroupReleaseAgentModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1010",
		Version:     "1",
		Name:        "Cgroups release agent file modification",
		EventName:   "cgroup_release_agent",
		Description: "An attempt to modify Cgroup release agent file was detected. Cgroups are a Linux kernel feature which limits the resource usage of a set of processes. Adversaries may use this feature for container escaping.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "privilege-escalation",
			"Technique":            "Escape to Host",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665",
			"external_id":          "T1611",
		},
	}, nil
}

func (sig *CgroupReleaseAgentModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "container"},
		{Source: "tracee", Name: "security_inode_rename", Origin: "container"},
	}, nil
}

func (sig *CgroupReleaseAgentModification) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	basename := ""

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

			basename = path.Base(pathname)
		}
	case "security_inode_rename":
		newPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "new_path")
		if err != nil {
			return err
		}

		basename = path.Base(newPath)
	}

	if basename == sig.releaseAgentName {
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

func (sig *CgroupReleaseAgentModification) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *CgroupReleaseAgentModification) Close() {}
