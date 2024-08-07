package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIPv6 struct {
	cb detect.SignatureHandler
}

var e2eIPv6Metadata = detect.SignatureMetadata{
	ID:          "IPv6",
	EventName:   "IPv6",
	Version:     "0.1.0",
	Name:        "Network IPv6 Test",
	Description: "Network E2E Tests: IPv6",
	Tags:        []string{"e2e", "network"},
}

func (sig *e2eIPv6) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIPv6) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eIPv6Metadata, nil
}

func (sig *e2eIPv6) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_ipv6"},
	}, nil
}

func (sig *e2eIPv6) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "net_packet_ipv6":
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

		ipv6, err := helpers.GetProtoIPv6ByName(eventObj, "proto_ipv6")
		if err != nil {
			return err
		}

		// check values for detection

		if src != "fd6e:a63d:71f:2f4::2" || dst != "fd6e:a63d:71f:2f4::1" {
			return nil
		}

		if ipv6.Version != 6 || ipv6.HopLimit != 64 ||
			ipv6.SrcIP != "fd6e:a63d:71f:2f4::2" ||
			ipv6.DstIP != "fd6e:a63d:71f:2f4::1" {
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

func (sig *e2eIPv6) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIPv6) Close() {}
