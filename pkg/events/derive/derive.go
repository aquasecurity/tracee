package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// DeriveFunction is a function prototype for a function that receives an event as
// argument and may produce a new event if relevant.
// It returns a derived or empty event, depending on successful derivation,
// and an error if one occurred.
type DeriveFunction func(trace.Event) ([]trace.Event, []error)

// Table defines a table between events and events they can be derived into corresponding to a deriveFunction
// The Enabled flag is used in order to skip derivation of unneeded events.
type Table map[events.ID]map[events.ID]struct {
	DeriveFunction DeriveFunction
	Enabled        func() bool
}

// Register registers a new derivation handler
func (t Table) Register(deriveFrom, deriveTo events.ID, deriveCondition func() bool, deriveLogic DeriveFunction) error {
	if t[deriveFrom] == nil {
		t[deriveFrom] = make(map[events.ID]struct {
			DeriveFunction DeriveFunction
			Enabled        func() bool
		})
	}

	if _, ok := t[deriveFrom][deriveTo]; ok {
		return alreadyRegisteredError(deriveFrom, deriveTo)
	}
	t[deriveFrom][deriveTo] = struct {
		DeriveFunction DeriveFunction
		Enabled        func() bool
	}{
		DeriveFunction: deriveLogic,
		Enabled:        deriveCondition,
	}
	return nil
}

// DeriveEvent takes a trace.Event and checks if it can derive additional events from it as defined by a derivationTable.
func (t Table) DeriveEvent(event trace.Event) ([]trace.Event, []error) {
	derivatives := []trace.Event{}
	errors := []error{}
	deriveFns := t[events.ID(event.EventID)]
	for id, deriveFn := range deriveFns {
		if deriveFn.Enabled() {
			derivative, errs := deriveFn.DeriveFunction(event)
			for _, err := range errs {
				errors = append(errors, deriveError(id, err))
			}
			derivatives = append(derivatives, derivative...)
		}
	}

	return derivatives, errors
}

// deriveBase is a struct for the necessary information from an event definition to create a derived event
type deriveBase struct {
	Name   string
	ID     int
	Params []trace.ArgMeta
}

// deriveArgsFunction defines the logic of deriving an Event.
// It checks the base event and produces arguments for the derived event.
// If an event can't be derived, the returned arguments should be `nil`.
type deriveArgsFunction func(event trace.Event) ([]interface{}, error)

// multiDeriveArgsFunction defines the logic of deriving multiple Events.
// It checks the event and produce the arguments of multiple derived event.
// If no event is derived, then the returned args should equal `nil`.
// To enable error handling of more than one failed derived events,
// all errors while events derivation should be appended to a list.
type multiDeriveArgsFunction func(event trace.Event) ([][]interface{}, []error)

// deriveSingleEvent create an deriveFunction which generates a single derive trace.Event.
// The event will be created using the original event information, the ID given and resulting
// arguments from the function.
// The arguments will be inserted in order, so they should match the resulting definition argument order.
// If the returned arguments are nil - no event will be derived.
// This function is an envelope for the deriveMultipleEvents function, to make it easier to create single event
// derivation function.
func deriveSingleEvent(id events.ID, deriveArgs deriveArgsFunction) DeriveFunction {
	singleDerive := func(event trace.Event) ([][]interface{}, []error) {
		var multiArgs [][]interface{}
		var errs []error
		args, err := deriveArgs(event)
		if args != nil {
			multiArgs = append(multiArgs, args)
		}
		if err != nil {
			errs = append(errs, err)
		}
		return multiArgs, errs
	}
	return deriveMultipleEvents(id, singleDerive)
}

// deriveMultipleEvents create an deriveFunction to generate multiple derive trace.Events.
// The events will be created using the original event information, the ID given and the arguments given.
// The order of the arguments given will match the order in the event definition, so make sure the order match
// the order of the params in the events.event struct of the event under events.Definitions.
// If the arguments given is nil, then no event will be derived.
func deriveMultipleEvents(id events.ID, multiDeriveArgsFunc multiDeriveArgsFunction) DeriveFunction {
	skeleton := makeDeriveBase(id)
	return func(event trace.Event) ([]trace.Event, []error) {
		multiArgs, errs := multiDeriveArgsFunc(event)
		if multiArgs == nil {
			return []trace.Event{}, errs
		}
		var derivedEvents []trace.Event
		for _, args := range multiArgs {
			de, err := buildDerivedEvent(&event, skeleton, args)
			if err != nil {
				errs = append(errs, err)
			} else {
				derivedEvents = append(derivedEvents, de)
			}
		}
		return derivedEvents, errs
	}
}

// buildDerivedEvent create a new derived event from given event values, adjusted by the derived event skeleton meta-data.
// This method enables using the context of the base event, but with the new arguments and meta-data of the derived one.
func buildDerivedEvent(baseEvent *trace.Event, skeleton deriveBase, argsValues []interface{}) (trace.Event, error) {
	if len(skeleton.Params) != len(argsValues) {
		return trace.Event{}, unexpectedArgCountError(skeleton.Name, len(skeleton.Params), len(argsValues))
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

// store as static variable for mocking in tests
var getEventDefinition = events.Definitions.Get

func makeDeriveBase(eventID events.ID) deriveBase {
	def := getEventDefinition(eventID)
	return deriveBase{
		Name:   def.Name,
		ID:     int(eventID),
		Params: def.Params,
	}
}
