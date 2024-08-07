package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type StdioOverSocket struct {
	cb         detect.SignatureHandler
	legitPorts []string
}

var stdioOverSocketMetadata = detect.SignatureMetadata{
	ID:          "TRC-101",
	Version:     "2",
	Name:        "Process standard input/output over socket detected",
	EventName:   "stdio_over_socket",
	Description: "A process has its standard input/output redirected to a socket. This behavior is the base of a Reverse Shell attack, which is when an interactive shell being invoked from a target machine back to the attacker's machine, giving it interactive control over the target. Adversaries may use a Reverse Shell to retain control over a compromised target while bypassing security measures like network firewalls.",
	Properties: map[string]interface{}{
		"Severity":             3,
		"Category":             "execution",
		"Technique":            "Unix Shell",
		"Kubernetes_Technique": "",
		"id":                   "attack-pattern--a9d4b653-6915-42af-98b2-5758c4ceee56",
		"external_id":          "T1059.004",
	},
}

func (sig *StdioOverSocket) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.legitPorts = []string{"", "0"}
	return nil
}

func (sig *StdioOverSocket) GetMetadata() (detect.SignatureMetadata, error) {
	return stdioOverSocketMetadata, nil
}

func (sig *StdioOverSocket) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_socket_connect", Origin: "*"},
		{Source: "tracee", Name: "socket_dup", Origin: "*"},
	}, nil
}

func (sig *StdioOverSocket) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	var sockfd int
	var err error

	switch eventObj.EventName {
	case "security_socket_connect":
		sockfd, err = helpers.GetTraceeIntArgumentByName(eventObj, "sockfd")
		if err != nil {
			return err
		}
	case "socket_dup":
		sockfd, err = helpers.GetTraceeIntArgumentByName(eventObj, "newfd")
		if err != nil {
			return err
		}
	}

	if sockfd != 0 && sockfd != 1 && sockfd != 2 {
		return nil
	}

	remoteAddr, err := helpers.GetRawAddrArgumentByName(eventObj, "remote_addr")
	if err != nil {
		return err
	}

	supportedFamily, err := helpers.IsInternetFamily(remoteAddr)
	if err != nil {
		return err
	}
	if !supportedFamily {
		return nil
	}

	port, err := helpers.GetPortFromRawAddr(remoteAddr)
	if err != nil {
		return err
	}

	for _, legitPort := range sig.legitPorts {
		if port == legitPort {
			return nil
		}
	}

	ip, err := helpers.GetIPFromRawAddr(remoteAddr)
	if err != nil {
		return err
	}

	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	sig.cb(&detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data: map[string]interface{}{
			"IP address":      ip,
			"Port":            port,
			"File descriptor": sockfd,
		},
	})

	return nil
}

func (sig *StdioOverSocket) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *StdioOverSocket) Close() {}
