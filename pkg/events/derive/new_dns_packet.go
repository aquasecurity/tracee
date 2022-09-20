package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// DNS Requests

func NewDnsRequest() deriveFunction {
	return deriveSingleEvent(events.NewDnsRequest, deriveNewDnsRequestArgs())
}

func deriveNewDnsRequestArgs() deriveArgsFunction {
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

// DNS Requests

func NewDnsResponse() deriveFunction {
	return deriveSingleEvent(events.NewDnsResponse, deriveNewDnsResponseArgs())
}

func deriveNewDnsResponseArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {

		error01Str := "couldn't find argument name nothing in event %s"
		error01 := fmt.Errorf(error01Str, event.EventName)

		nothingArg := events.GetArg(&event, "nothing")
		if nothingArg == nil {
			return nil, error01
		}

		// TODO: return nil, nil if not a response (e.g)

		return []interface{}{nothingArg.Value}, nil
	}
}
