package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIPv4 struct {
	cb detect.SignatureHandler
}

var e2eIPv4Metadata = detect.SignatureMetadata{
	ID:          "IPv4",
	EventName:   "IPv4",
	Version:     "0.1.0",
	Name:        "Network IPv4 Test",
	Description: "Network E2E Tests: IPv4",
	Tags:        []string{"e2e", "network"},
}

func (sig *e2eIPv4) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIPv4) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eIPv4Metadata, nil
}

func (sig *e2eIPv4) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_ipv4"},
	}, nil
}

func (sig *e2eIPv4) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "net_packet_ipv4":
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

		ipv4, err := helpers.GetProtoIPv4ByName(eventObj, "proto_ipv4")
		if err != nil {
			return err
		}

		// check values for detection

		if src != "172.16.17.2" || dst != "172.16.17.1" {
			return nil
		}

		if ipv4.Version != 4 || ipv4.IHL != 5 ||
			ipv4.SrcIP != "172.16.17.2" ||
			ipv4.DstIP != "172.16.17.1" {
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

func (sig *e2eIPv4) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIPv4) Close() {}
