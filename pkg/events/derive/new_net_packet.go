package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func NewNetPacket() deriveFunction {
	return deriveSingleEvent(events.NewNetPacket, deriveNewNetPacketArgs())
}

func deriveNewNetPacketArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {

		error01Str := "couldn't find argument name nothing in event %s"
		error01 := fmt.Errorf(error01Str, event.EventName)

		nothingArg := events.GetArg(&event, "nothing")
		if nothingArg == nil {
			return nil, error01
		}

		return []interface{}{nothingArg.Value}, nil
	}
}
