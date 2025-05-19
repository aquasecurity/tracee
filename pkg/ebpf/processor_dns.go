package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/pipeline"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func (t *Tracee) populateDnsCache(event *pipeline.Event) error {
	if event.EventID != int(events.NetPacketDNS) {
		// Sanity check.
		return fmt.Errorf("received event %s: event is not net_packet_dns_response", event.EventName)
	}

	err := t.dnsCache.Add(event)
	if err != nil {
		logger.Errorw("error caching dns data from event", "error", err)
	}
	return nil
}
