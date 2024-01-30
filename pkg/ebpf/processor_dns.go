package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func (t *Tracee) populateDnsCache(event *trace.Event) error {
	if event.EventID != int(extensions.NetPacketDNS) {
		// Sanity check.
		return fmt.Errorf("received event %s: event is not net_packet_dns_response", event.EventName)
	}

	err := t.dnsCache.Add(event)
	if err != nil {
		logger.Errorw("error caching dns data from event", "error", err)
	}
	return nil
}
