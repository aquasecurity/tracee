package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eICMPv6 struct {
	cb detect.SignatureHandler
}

var e2eICMPv6Metadata = detect.SignatureMetadata{
	ID:          "ICMPv6",
	EventName:   "ICMPv6",
	Version:     "0.1.0",
	Name:        "Network ICMPv6 Test",
	Description: "Network E2E Tests: ICMPv6",
	Tags:        []string{"e2e", "network"},
}

func (sig *e2eICMPv6) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eICMPv6) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eICMPv6Metadata, nil
}

func (sig *e2eICMPv6) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_icmpv6"},
	}, nil
}

func (sig *e2eICMPv6) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "net_packet_icmpv6":
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

		icmpv6, err := helpers.GetProtoICMPv6ByName(eventObj, "proto_icmpv6")
		if err != nil {
			return err
		}

		// check values for detection

		if src != "fd6e:a63d:71f:2f4::1" || dst != "fd6e:a63d:71f:2f4::2" {
			return nil
		}

		if icmpv6.TypeCode != "EchoReply" {
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

func (sig *e2eICMPv6) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eICMPv6) Close() {}
