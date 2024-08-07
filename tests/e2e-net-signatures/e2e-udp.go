package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eUDP struct {
	cb detect.SignatureHandler
}

var e2eUDPMetadata = detect.SignatureMetadata{
	ID:          "UDP",
	EventName:   "UDP",
	Version:     "0.1.0",
	Name:        "Network UDP Test",
	Description: "Network E2E Tests: UDP",
	Tags:        []string{"e2e", "network"},
}

func (sig *e2eUDP) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eUDP) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eUDPMetadata, nil
}

func (sig *e2eUDP) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_udp"},
	}, nil
}

func (sig *e2eUDP) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "net_packet_udp":
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

		udp, err := helpers.GetProtoUDPByName(eventObj, "proto_udp")
		if err != nil {
			return err
		}

		// check values for detection

		if src != "172.16.17.2" || dst != "172.16.17.1" {
			return nil
		}

		if udp.DstPort != 8090 {
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

func (sig *e2eUDP) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eUDP) Close() {}
