package main

import (
	"errors"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// HOWTO: The way to trigger this test signature is to execute:
//
//        curl google.com
//
//        This will cause it trigger once and reset it status.

type e2eHTTP struct {
	cb  detect.SignatureHandler
	log detect.Logger
}

func (sig *e2eHTTP) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.log = ctx.Logger
	return nil
}

func (sig *e2eHTTP) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "HTTP",
		EventName:   "HTTP",
		Version:     "0.1.0",
		Name:        "Network HTTP Test",
		Description: "Network E2E Tests: HTTP",
		Tags:        []string{"e2e", "network"},
	}, nil
}

func (sig *e2eHTTP) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_http"},
	}, nil
}

func (sig *e2eHTTP) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	if eventObj.ProcessName != "curl" {
		return nil
	}

	if eventObj.EventName == "net_packet_http" {
		// validate tast context
		if eventObj.HostName == "" {
			return nil
		}

		http, err := eventObj.GetProtoHTTPByName("proto_http")
		if err != nil {
			return err
		}

		if http.Direction != "request" && http.Direction != "response" {
			return nil
		}

		md, err := eventObj.GetPacketMetadata("metadata")
		if err != nil {
			return err
		}

		if !testHttpDirectionAndPacketDirection(&md, &http) {
			sig.log.Infow("direction mismatch", "direction", http.Direction, "packet_direction", md.Direction)
			return nil
		}

		if !strings.HasPrefix(http.Protocol, "HTTP/") {
			sig.log.Infow("not HTTP", "protocol", http.Protocol)
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

func (sig *e2eHTTP) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eHTTP) Close() {}

func testHttpDirectionAndPacketDirection(md *trace.PacketMetadata, http *trace.ProtoHTTP) bool {
	// This test is done in the context of a curl request, but if it was in the context
	// of a server then the direction of the packet would be opposite to the http direction
	return (http.Direction == "request" && md.Direction == trace.PacketEgress) ||
		(http.Direction == "response" && md.Direction == trace.PacketIngress)
}
