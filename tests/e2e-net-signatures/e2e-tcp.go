package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eTCP struct {
	cb detect.SignatureHandler
}

var e2eTCPMetadata = detect.SignatureMetadata{
	ID:          "TCP",
	EventName:   "TCP",
	Version:     "0.1.0",
	Name:        "Network TCP Test",
	Description: "Network E2E Tests: TCP",
	Tags:        []string{"e2e", "network"},
}

func (sig *e2eTCP) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eTCP) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eTCPMetadata, nil
}

func (sig *e2eTCP) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_tcp"},
	}, nil
}

func (sig *e2eTCP) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "net_packet_tcp":
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

		tcp, err := helpers.GetProtoTCPByName(eventObj, "proto_tcp")
		if err != nil {
			return err
		}

		// check values for detection

		if src != "172.16.17.1" || dst != "172.16.17.2" {
			return nil
		}

		if tcp.SrcPort != 8090 ||
			tcp.ACK != 1 ||
			tcp.RST != 0 ||
			tcp.URG != 0 ||
			tcp.SYN != 0 ||
			tcp.FIN != 0 {
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

func (sig *e2eTCP) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eTCP) Close() {}
