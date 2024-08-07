package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eDnsDataSource struct {
	cb      detect.SignatureHandler
	dnsData detect.DataSource
}

var e2eDnsDataSourceMetadata = detect.SignatureMetadata{
	ID:          "DNS_DATA_SOURCE",
	EventName:   "DNS_DATA_SOURCE",
	Version:     "0.1.0",
	Name:        "DNS Data Source Test",
	Description: "Instrumentation events E2E Tests: DNS Data Source Test",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eDnsDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	dnsData, ok := ctx.GetDataSource("tracee", "dns")
	if !ok {
		return fmt.Errorf("dns data source not registered")
	}
	if dnsData.Version() > 1 {
		return fmt.Errorf("dns data source version not supported, please update this signature")
	}
	sig.dnsData = dnsData
	return nil
}

func (sig *e2eDnsDataSource) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eDnsDataSourceMetadata, nil
}

func (sig *e2eDnsDataSource) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exit"},
	}, nil
}

func (sig *e2eDnsDataSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exit":
		if eventObj.Executable.Path != "/usr/bin/ping" {
			return nil // irrelevant code path
		}

		dns, err := sig.dnsData.Get("google.com")
		if err != nil {
			return fmt.Errorf("failed to find dns data in data source: %v", err)
		}

		ipResults, ok := dns["ip_addresses"].([]string)
		if !ok {
			return fmt.Errorf("failed to extract ip results")
		}
		if len(ipResults) < 1 {
			return fmt.Errorf("ip results were empty")
		}

		dnsResults, ok := dns["dns_queries"].([]string)
		if !ok {
			return fmt.Errorf("failed to extract dns results")
		}
		if len(dnsResults) < 1 {
			return fmt.Errorf("dns results were empty")
		}
		if dnsResults[0] != "google.com" {
			return fmt.Errorf("bad dns query: %s", dnsResults[0])
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

func (sig *e2eDnsDataSource) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eDnsDataSource) Close() {}
