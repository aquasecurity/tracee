package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
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
// writing to the map may have unintentional consequences, avoid doing so
func (filter *ArgFilter) GetEventFilters(eventID events.ID) map[string]Filter {
	return filter.filters[eventID]
}

func (filter *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if !filter.Enabled() {
		return true
	}

	// TODO: remove once events params are introduced
	//       i.e. print_mem_dump.params.symbol_name=system:security_file_open
	// events.PrintMemDump bypass was added due to issue #2546
	// because it uses usermode applied filters as parameters for the event,
	// which occurs after filtering
	if eventID == events.PrintMemDump {
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
			return false
		}
		// TODO: use type assertion instead of string conversion
		if argName != "syscall" {
			argVal = fmt.Sprint(argVal)
		}
		res := filter.Filter(argVal)
		if !res {
			return false
		}
	}

	return true
}

func (filter *ArgFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	// Event argument filter has the following format: "event.args.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"
	parts := strings.Split(filterName, ".")
	if len(parts) != 3 {
		return InvalidExpression(filterName + operatorAndValues)

	}
	if parts[1] != "args" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	eventName := parts[0]
	argName := parts[2]

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

	// if the event is a signature event, we allow filtering on dynamic argument
	if !argFound && !eventDefinition.IsASignatureEvent() {
		return InvalidEventArgument(argName)
	}

	err := filter.parseFilter(id, argName, operatorAndValues, func() Filter {
		// TODO: map argument type to an appropriate filter constructor
		return NewStringFilter()
	})
	if err != nil {
		return errfmt.WrapError(err)
	}

	filter.Enable()

	return nil
}

// parseFilter adds an argument filter with the relevant filterConstructor
// The user must responsibly supply a reliable Filter object.
func (filter *ArgFilter) parseFilter(id events.ID, argName string, operatorAndValues string, filterConstructor func() Filter) error {
	if _, ok := filter.filters[id]; !ok {
		filter.filters[id] = map[string]Filter{}
	}

	if _, ok := filter.filters[id][argName]; !ok {
		// store new event arg filter if missing
		argFilter := filterConstructor()
		filter.filters[id][argName] = argFilter
	}

	// extract the arg filter and parse expression into it
	argFilter := filter.filters[id][argName]
	err := argFilter.Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// store the arg filter again
	filter.filters[id][argName] = argFilter

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
