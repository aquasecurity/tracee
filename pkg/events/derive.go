package events

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

// DeriveFunction is a function prototype for a function that receives an event as
// argument and may produce a new event if relevant.
// It returns a derived or empty event, depending on successful derivation,
// a bool indicating if an event was derived, and an error if one occurred.
type DeriveFunction func(trace.Event) (trace.Event, bool, error)

// DerivationTable defines a table between events and events they can be derived into corresponding to some deriveFn
type DerivationTable map[ID]map[ID]struct {
	Function DeriveFunction
	Enabled  bool //practically this field is to drop derivation of unneeded events
}

// Derive takes a trace.Event and checks if it can derive additional events from it
// as defined by tracee's eventDerivations map.
// The map is initialized in the above function
func Derive(event trace.Event, derivationTable DerivationTable) ([]trace.Event, []error) {
	derivatives := []trace.Event{}
	errors := []error{}
	deriveFns := derivationTable[ID(event.EventID)]
	for id, deriveFn := range deriveFns {
		if deriveFn.Enabled {
			derivative, derived, err := deriveFn.Function(event)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to derive event %d: %v", id, err))
			} else if derived {
				derivatives = append(derivatives, derivative)
			}
		}
	}

	return derivatives, errors
}
