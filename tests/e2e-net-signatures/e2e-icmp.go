package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eICMP struct {
	cb detect.SignatureHandler
}

var e2eICMPMetadata = detect.SignatureMetadata{
	ID:          "ICMP",
	EventName:   "ICMP",
	Version:     "0.1.0",
	Name:        "Network ICMP Test",
	Description: "Network E2E Tests: ICMP",
	Tags:        []string{"e2e", "network"},
}

func (sig *e2eICMP) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eICMP) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eICMPMetadata, nil
}

func (sig *e2eICMP) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_icmp"},
	}, nil
}

func (sig *e2eICMP) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "net_packet_icmp":
		// validate tast context
		if eventObj.HostName == "" {
			return nil
		}

		src, err := helpers.GetTraceeStringArgumentByName(eventObj, "src")
		if err != nil {
			return err
		}

		dst, err := helpers.GetTraceeStringArgumentByName(eventObj, "dst")
		if err != nil {
			return err
		}

		icmp, err := helpers.GetProtoICMPByName(eventObj, "proto_icmp")
		if err != nil {
			return err
		}

		// check values for detection

		if src != "172.16.17.1" || dst != "172.16.17.2" {
			return nil
		}

		if icmp.TypeCode != "EchoReply" {
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

func (sig *e2eICMP) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eICMP) Close() {}
