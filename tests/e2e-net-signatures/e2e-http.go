package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
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
	cb detect.SignatureHandler
}

func (sig *e2eHTTP) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eHTTP) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "HTTP",
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
		return fmt.Errorf("failed to cast event's payload")
	}

	if eventObj.EventName == "net_packet_http" {
		http, err := helpers.GetProtoHTTPByName(eventObj, "proto_http")
		if err != nil {
			return err
		}

		if http.Direction != "request" && http.Direction != "response" {
			return nil
		}

		if !strings.HasPrefix(http.Protocol, "HTTP/") {
			return nil
		}

		m, _ := sig.GetMetadata()
		sig.cb(detect.Finding{
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
