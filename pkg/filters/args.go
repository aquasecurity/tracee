package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ArgFilter struct {
	Filters map[events.ID]map[string]*StringFilter // key to the first map is event id, and to the second map the argument name
	enabled bool
}

func (filter *ArgFilter) Enable() {
	filter.enabled = true
	for _, filterMap := range filter.Filters {
		for _, f := range filterMap {
			f.Enable()
		}
	}
}

func (filter *ArgFilter) Disable() {
	filter.enabled = false
	for _, filterMap := range filter.Filters {
		for _, f := range filterMap {
			f.Disable()
		}
	}
}

func (filter *ArgFilter) Enabled() bool {
	return filter.enabled
}

func (filter *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if !filter.enabled {
		return true
	}
	for argName, filter := range filter.Filters[eventID] {
		var argVal interface{}
		ok := false
		for _, arg := range args {
			if arg.Name == argName {
				argVal = arg.Value
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		// TODO: use type assertion instead of string conversion
		argValStr := fmt.Sprint(argVal)
		if !filter.Filter(argValStr) {
			return false
		}
	}
	return true
}

func (filter *ArgFilter) Add(filterReq protocol.Filter) error {
	// Event argument filter has the following format: "event.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"

	field := filterReq.Field
	parts := strings.Split(field, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for arg filter: %s", field)
	}
	eventName := parts[0]
	argName := parts[1]

	id, ok := events.Definitions.GetID(eventName)
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

	eventDefinition := events.Definitions.Get(id)
	eventParams := eventDefinition.Params

	// check if argument name exists for this event
	argFound := false
	for i := range eventParams {
		if eventParams[i].Name == argName {
			argFound = true
			break
		}
	}

	if !argFound {
		return fmt.Errorf("invalid argument filter argument name: %s", argName)
	}

	// Treat operatorAndValues as a string filter to avoid code duplication
	strFilter := NewStringFilter()
	strFilter.Add(filterReq)

	if _, ok := filter.Filters[id]; !ok {
		filter.Filters[id] = make(map[string]*StringFilter)
	}

	if _, ok := filter.Filters[id][argName]; !ok {
		filter.Filters[id][argName] = strFilter
	}

	return nil
}
