package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type IllegitimateShell struct {
	cb                     detect.SignatureHandler
	shellNames             []string
	webServersProcessNames []string
}

var illegitimateShellMetadata = detect.SignatureMetadata{
	ID:          "TRC-1016",
	Version:     "1",
	Name:        "Web server spawned a shell",
	EventName:   "illegitimate_shell",
	Description: "A web-server program on your server spawned a shell program. Shell is the linux command-line program, web servers usually don't run shell programs, so this alert might indicate an adversary is exploiting a web server program to gain command execution on the server.",
	Properties: map[string]interface{}{
		"Severity":             2,
		"Category":             "initial-access",
		"Technique":            "Exploit Public-Facing Application",
		"Kubernetes_Technique": "",
		"id":                   "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
		"external_id":          "T1190",
	},
}

func (sig *IllegitimateShell) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.shellNames = []string{"/ash", "/bash", "/csh", "/ksh", "/sh", "/tcsh", "/zsh", "/dash"}
	sig.webServersProcessNames = []string{"nginx", "httpd", "httpd-foregroun", "http-nio", "lighttpd", "apache", "apache2"}
	return nil
}

func (sig *IllegitimateShell) GetMetadata() (detect.SignatureMetadata, error) {
	return illegitimateShellMetadata, nil
}

func (sig *IllegitimateShell) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_bprm_check", Origin: "*"},
	}, nil
}

func (sig *IllegitimateShell) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "security_bprm_check":
		for _, webServersProcessName := range sig.webServersProcessNames {
			if webServersProcessName == eventObj.ProcessName {
				pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
				if err != nil {
					return err
				}

				for _, shellName := range sig.shellNames {
					if strings.HasSuffix(pathname, shellName) {
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
				}
			}
		}
	}

	return nil
}

func (sig *IllegitimateShell) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *IllegitimateShell) Close() {}
