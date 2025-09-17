package main

import (
	"errors"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eDnsRequestKernel struct {
	cb               detect.SignatureHandler
	seenUbufRequest  bool
	seenIovecRequest bool
}

func (sig *e2eDnsRequestKernel) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.seenUbufRequest = false
	sig.seenIovecRequest = false

	return nil
}

func (sig *e2eDnsRequestKernel) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "DNS_REQUEST_KERNEL",
		EventName:   "DNS_REQUEST_KERNEL",
		Version:     "0.1.0",
		Name:        "DNS Request Kernel Test",
		Description: "Instrumentation events E2E Tests: DNS Request Kernel",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eDnsRequestKernel) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "dns_request_kernel"},
	}, nil
}

func (sig *e2eDnsRequestKernel) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "dns_request_kernel":
		// Check if we got a DNS request for google.com
		hostname, err := eventObj.GetStringArgumentByName("hostname")
		if err != nil {
			return nil // Don't fail on missing hostname
		}
		if hostname != "google.com" {
			return nil
		}

		switch eventObj.ProcessName {
		case "dns_iovec_clien": // Name is truncated to 15 characters by tracee
			sig.seenIovecRequest = true
		case "dns_lookup_c":
			sig.seenUbufRequest = true
		}

		if !(sig.seenUbufRequest && sig.seenIovecRequest) {
			return nil
		}

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data: map[string]interface{}{
				"hostname": hostname,
			},
		})
	}

	return nil
}

func (sig *e2eDnsRequestKernel) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eDnsRequestKernel) Close() {}
