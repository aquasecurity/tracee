package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type ArgFilter struct {
	filters map[events.ID]map[string]Filter
	enabled bool
}

func NewArgFilter() *ArgFilter {
	return &ArgFilter{
		filters: map[events.ID]map[string]Filter{},
		enabled: false,
	}
}

// GetEventFilters returns the argument filters map for a specific event
// writing to the map may have unintentional consenquences, avoid doing so
func (filter *ArgFilter) GetEventFilters(eventID events.ID) map[string]Filter {
	return filter.filters[eventID]
}

func (filter *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if !filter.Enabled() {
		return true
	}

	for argName, filter := range filter.filters[eventID] {
		found := false
		var argVal interface{}
		for _, arg := range args {
			if arg.Name == argName {
				found = true
				argVal = arg.Value
				break
			}
		}
		if !found {
			return true
		}
		// TODO: use type assertion instead of string conversion
		argValStr := fmt.Sprint(argVal)
		res := filter.Filter(argValStr)
		if !res {
			return false
		}
	}
	return true
}

func (filter *ArgFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	// Event argument filter has the following format: "event.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 {
		return InvalidExpression(filterName + operatorAndValues)
	}
	eventName := splitFilter[0]
	argName := splitFilter[1]

	if eventName == "" || argName == "" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	id, ok := eventsNameToID[eventName]
	if !ok {
		return InvalidEventName(eventName)
	}

	eventDefinition, ok := events.Definitions.GetSafe(id)
	if !ok {
		return InvalidEventName(eventName)
	}
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
		return InvalidEventArgument(argName)
	}

	if _, ok := filter.filters[id]; !ok {
		filter.filters[id] = map[string]Filter{}
	}

	if _, ok := filter.filters[id][argName]; !ok {
		// store new event arg filter if missing
		argFilter := NewStringFilter()
		filter.filters[id][argName] = argFilter
	}

	// extract the arg filter and parse expression into it
	argFilter := filter.filters[id][argName]
	err := argFilter.Parse(operatorAndValues)
	if err != nil {
		return err
	}

	// store the arg filter again
	filter.filters[id][argName] = argFilter

	filter.Enable()

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
