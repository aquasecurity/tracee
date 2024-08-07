package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eSecurityInodeRename struct {
	cb detect.SignatureHandler
}

var e2eSecurityInodeRenameMetadata = detect.SignatureMetadata{
	ID:          "SECURITY_INODE_RENAME",
	EventName:   "SECURITY_INODE_RENAME",
	Version:     "0.1.0",
	Name:        "security_inode_rename Test",
	Description: "Instrumentation events E2E Tests: security_inode_rename",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eSecurityInodeRename) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eSecurityInodeRename) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eSecurityInodeRenameMetadata, nil
}

func (sig *e2eSecurityInodeRename) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_inode_rename"},
	}, nil
}

func (sig *e2eSecurityInodeRename) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "security_inode_rename":
		oldPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "old_path")
		if err != nil {
			return err
		}

		newPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "new_path")
		if err != nil {
			return err
		}

		// ATTENTION: Both, oldPath and newPath are relative to the filesystem they're in:
		// /tmp/aaa.txt comes as aaa.txt if /tmp is a tmpfs and not part of the root filesystem.

		if !strings.HasSuffix(oldPath, "aaa.txt") || !strings.HasSuffix(newPath, "bbb.txt") {
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

func (sig *e2eSecurityInodeRename) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eSecurityInodeRename) Close() {}
