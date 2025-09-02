package main

import (
	"errors"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// HOWTO: The way to trigger this test signature is to execute:
//
//        nslookup -type=mx    google.com   and then
//        nslookup -type=ns    google.com   and then
//        nslookup -type=soa   google.com
//
//        This will cause it trigger once and reset it status.

type e2eDNS struct {
	foundMX  bool
	foundNS  bool
	foundSOA bool
	cb       detect.SignatureHandler
	log      detect.Logger
}

func (sig *e2eDNS) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.foundMX = false  // proforma
	sig.foundNS = false  // proforma
	sig.foundSOA = false // proforma
	sig.log = ctx.Logger
	return nil
}

func (sig *e2eDNS) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "DNS",
		EventName:   "DNS",
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
		return errors.New("failed to cast event's payload")
	}

	if eventObj.EventName == "net_packet_dns" {
		// validate tast context
		if eventObj.HostName == "" {
			return nil
		}

		dns, err := eventObj.GetProtoDNSByName("proto_dns")
		if err != nil {
			return err
		}

		if len(dns.Answers) > 0 {
			for _, answer := range dns.Answers {
				// check if MX works
				if answer.MX.Name == "smtp.google.com" &&
					answer.MX.Preference == 10 {
					sig.foundMX = true
					sig.log.Infow("found MX", "name", answer.MX.Name, "preference", answer.MX.Preference)
				}
				// check if NS works
				if answer.NS == "ns1.google.com" {
					sig.foundNS = true
					sig.log.Infow("found NS", "name", answer.NS)
				}
				// check if SOA works
				if answer.SOA.RName == "dns-admin.google.com" {
					sig.foundSOA = true
					sig.log.Infow("found SOA", "name", answer.SOA.RName)
				}
			}
		}

		if !sig.foundMX || !sig.foundNS || !sig.foundSOA {
			return nil
		}

		if sig.foundMX && sig.foundNS && sig.foundSOA { // reset signature state
			sig.foundMX = false
			sig.foundNS = false
			sig.foundSOA = false
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

func (sig *e2eDNS) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eDNS) Close() {}
