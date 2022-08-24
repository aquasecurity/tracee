package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// NetPacket derives net_packet from net events with 'metadata' arg
func NetPacket() deriveFunction {
	return deriveSingleEvent(events.NetPacket, deriveNetPacketArgs())
}

func deriveNetPacketArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		metadataArg := events.GetArg(&event, "metadata")
		if metadataArg == nil {
			return nil, fmt.Errorf("couldn't find argument name metadata in event %s", event.EventName)
		}
		return []interface{}{*metadataArg}, nil
	}
}
