package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ArgFilter struct {
	filters map[events.ID]map[string]*eventArgFilter // key to the first map is event id, and to the second map the argument name
	enabled bool
}

type eventArgFilter struct {
	*StringFilter
}

func NewArgFilter(filters ...protocol.Filter) (*ArgFilter, error) {
	filter := &ArgFilter{
		filters: map[events.ID]map[string]*eventArgFilter{},
	}

	for _, f := range filters {
		err := filter.parse(f)
		if err != nil {
			return filter, err
		}
	}

	if len(filters) > 0 {
		filter.Enable()
	}

	return filter, nil
}

func (filter *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if !filter.Enabled() {
		return true
	}

	for argName, filter := range filter.filters[events.ID(eventID)] {
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
		return filter.Filter(argValStr)
	}
	return true
}

// GetEventFilters returns the argument filters map for a specific event
// writing to the map may have unintentional consenquences, avoid doing so
func (filter *ArgFilter) GetEventFilters(eventID events.ID) map[string]*eventArgFilter {
	return filter.filters[eventID]
}

func (filter *ArgFilter) parse(filterReq protocol.Filter) error {
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

	if _, ok := filter.filters[id]; !ok {
		filter.filters[id] = make(map[string]*eventArgFilter)
	}

	if _, ok := filter.filters[id][argName]; !ok {
		strFilter, err := NewStringFilter(filterReq)
		if err != nil {
			return err
		}
		eventFilter := &eventArgFilter{
			StringFilter: strFilter,
		}
		filter.filters[id][argName] = eventFilter
	}

	return nil
}

func (filter *ArgFilter) Enable() {
	filter.enabled = true
	for _, filterMap := range filter.filters {
		for _, f := range filterMap {
			f.Enable()
		}
	}
}

func (filter *ArgFilter) Disable() {
	filter.enabled = false
	for _, filterMap := range filter.filters {
		for _, f := range filterMap {
			f.Disable()
		}
	}
}

func (filter *ArgFilter) Enabled() bool {
	return filter.enabled
}
