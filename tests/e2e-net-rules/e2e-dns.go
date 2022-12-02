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
//        nslookup -type=mx uol.com.br      and then
//        nslookup -type=ns uol.com.br      and then
//        nslookup -type=soa uol.com.br     and then
//        nslookup -type=txt uol.com.br
//
//        This will cause it trigger once and reset it status.

type e2eDNS struct {
	foundMX   bool
	foundNS   bool
	foundSOA  bool
	foundTXTs bool
	cb        detect.SignatureHandler
}

func (sig *e2eDNS) Init(cb detect.SignatureHandler) error {
	sig.cb = cb
	sig.foundMX = false   // proforma
	sig.foundNS = false   // proforma
	sig.foundSOA = false  // proforma
	sig.foundTXTs = false // proforma
	return nil
}

func (sig *e2eDNS) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "DNS",
		Version:     "0.1.0",
		Name:        "Network DNS Test",
		Description: "Network E2E Tests: DNS",
		Tags:        []string{"e2e", "network"},
	}, nil
}

func (sig *e2eDNS) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "net_packet_dns"},
	}, nil
}

func (sig *e2eDNS) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	if eventObj.EventName == "net_packet_dns" {
		dns, err := helpers.GetProtoDNSByName(eventObj, "proto_dns")
		if err != nil {
			return err
		}

		if len(dns.Answers) > 0 {
			for _, answer := range dns.Answers {
				// check if MX works
				if answer.MX.Name == "mx.uol.com.br" && answer.MX.Preference == 10 {
					sig.foundMX = true
				}
				// check if NS works
				if answer.NS == "eliot.uol.com.br" {
					sig.foundNS = true
				}
				// check if SOA works
				if answer.SOA.RName == "root.uol.com.br" {
					sig.foundSOA = true
				}
				// check if TXTs works
				if answer.TXTs != nil && len(answer.TXTs) > 0 {
					for _, txt := range answer.TXTs {
						if strings.Contains(txt, "spf.uol.com.br") {
							sig.foundTXTs = true
						}
					}
				}
			}
		}

		if !sig.foundMX || !sig.foundNS || !sig.foundSOA || !sig.foundTXTs {
			return nil
		}

		if sig.foundMX && sig.foundNS && sig.foundSOA && sig.foundTXTs { // reset signature state
			sig.foundMX = false
			sig.foundNS = false
			sig.foundSOA = false
			sig.foundTXTs = false
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

func (sig *e2eDNS) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eDNS) Close() {}
