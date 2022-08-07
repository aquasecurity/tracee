package derive

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// Use as static variable for testability reasons
var getEventDefFunc = events.Definitions.Get

// eventSkeleton is a struct for the necessary information from an event definition to create the derived event
type eventSkeleton struct {
	Name   string
	ID     int
	Params []trace.ArgMeta
}

// deriveArgsFunction is the main logic of the derived event.
// It checks the event and produce the arguments of the derived event.
// If no event is derived, then the returned args should equal `nil`.
type deriveArgsFunction func(event trace.Event) ([]interface{}, error)

// singleEventDeriveFunc create an events.DeriveFunction to generate a single derive trace.Event.
// The event will be created using the original event information, the ID given and the arguments given.
// The order of the arguments given will match the order in the event definition, so make sure the order match
// the order of the params in the events.event struct of the event under events.Definitions.
// If the arguments given is nil, than no event will be derived.
func singleEventDeriveFunc(id events.ID, deriveArgsFunc deriveArgsFunction, eventBuilder func(*trace.Event) (trace.Event, error)) events.DeriveFunction {
	skeleton := makeEventSkeleton(id)
	return func(event trace.Event) ([]trace.Event, []error) {
		args, err := deriveArgsFunc(event)
		if err != nil {
			return nil, []error{err}
		}
		if args == nil {
			return []trace.Event{}, nil
		}
		baseEvent, err := eventBuilder(&event)
		if err != nil {
			return []trace.Event{}, []error{err}
		}
		de, err := newEvent(&baseEvent, skeleton, args)
		if err != nil {
			return []trace.Event{}, []error{err}
		}
		return []trace.Event{de}, nil
	}
}

// newEvent create a new derived event from given event values, adjusted by the derived event skeleton meta-data.
// This method enables using the context of the base event, but with the new arguments and meta-data of the derived one.
func newEvent(baseEvent *trace.Event, skeleton eventSkeleton, argsValues []interface{}) (trace.Event, error) {
	if len(skeleton.Params) != len(argsValues) {
		return trace.Event{}, fmt.Errorf("error while building derived event '%s' - expected %d arguments but given %d", skeleton.Name, len(skeleton.Params), len(argsValues))
	}
	de := *baseEvent
	de.EventID = skeleton.ID
	de.EventName = skeleton.Name
	de.ReturnValue = 0
	de.StackAddresses = make([]uint64, 1)
	de.Args = make([]trace.Argument, len(skeleton.Params))
	for i, value := range argsValues {
		de.Args[i] = trace.Argument{ArgMeta: skeleton.Params[i], Value: value}
	}
	de.ArgsNum = len(de.Args)
	return de, nil
}

func makeEventSkeleton(eventID events.ID) eventSkeleton {
	def := getEventDefFunc(eventID)
	return eventSkeleton{
		Name:   def.Name,
		ID:     int(eventID),
		Params: def.Params,
	}
}

func withOriginalContext(event *trace.Event) (trace.Event, error) {
	return *event, nil
}
