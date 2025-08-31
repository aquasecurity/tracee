package main

import (
	"errors"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eSecurityPathNotify struct {
	cb             detect.SignatureHandler
	log            detect.Logger
	found_dnotify  bool
	found_inotify  bool
	found_fanotify bool
}

func (sig *e2eSecurityPathNotify) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.log = ctx.Logger
	return nil
}

func (sig *e2eSecurityPathNotify) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "SECURITY_PATH_NOTIFY",
		EventName:   "SECURITY_PATH_NOTIFY",
		Version:     "0.1.0",
		Name:        "Security Path Notify Test",
		Description: "Instrumentation events E2E Tests: Security Path Notify",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eSecurityPathNotify) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_path_notify"},
	}, nil
}

func (sig *e2eSecurityPathNotify) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "security_path_notify":
		pathName, err := eventObj.GetStringArgumentByName("pathname")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if strings.HasSuffix(pathName, "/dnotify_test") {
			sig.found_dnotify = true
			sig.log.Infow("found dnotify_test", "pathname", pathName)
		} else if strings.HasSuffix(pathName, "/inotify_test") {
			sig.found_inotify = true
			sig.log.Infow("found inotify_test", "pathname", pathName)
		} else if strings.HasSuffix(pathName, "/fanotify_test") {
			sig.found_fanotify = true
			sig.log.Infow("found fanotify_test", "pathname", pathName)
		} else {
			return nil
		}

		if !sig.found_dnotify || !sig.found_inotify || !sig.found_fanotify {
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

func (sig *e2eSecurityPathNotify) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eSecurityPathNotify) Close() {}
