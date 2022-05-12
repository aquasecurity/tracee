package derived

import "github.com/aquasecurity/tracee/types/trace"

// DeriveFn is a function prototype for a function that receives an event as
// argument and may produce a new event if relevant.
// It returns list of derived events, which might be empty depending on successful derivation,
// a bool indicating if an event was derived, and an error if one occurred.
type DeriveFn func(trace.Event) ([]trace.Event, bool, error)

// IDerivedEventGenerator is an interface for derived events generator class.
// The main purpose of it is to create derived events given an event.
// To generate derived event, the GenerateDerivedFn function should be used with initialized generator.
type IDerivedEventGenerator interface {
	GenerateEvents(event trace.Event) ([]trace.Event, bool, error)
}

func GenerateDerivedFn(generator IDerivedEventGenerator) DeriveFn {
	return func(event trace.Event) ([]trace.Event, bool, error) {
		return generator.GenerateEvents(event)
	}
}

// EventSkeleton is a struct for the necessary information from an event definition to create the derived event
type EventSkeleton struct {
	Name   string
	ID     int
	Params []trace.ArgMeta
}
