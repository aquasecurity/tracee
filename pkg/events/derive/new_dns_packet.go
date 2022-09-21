package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// DNS Requests

func NewNetPacketDNSRequest() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNSRequest, deriveNetPacketDNSRequest())
}

func deriveNetPacketDNSRequest() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		return []interface{}{""}, nil
	}
}

// DNS Requests

func NewNetPacketDNSResponse() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNSResponse, deriveNetPacketDNSResponse())
}

func deriveNetPacketDNSResponse() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		return []interface{}{""}, nil
	}
}
