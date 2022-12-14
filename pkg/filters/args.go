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
			return false // always filter if argument does not exist
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

	if !argFound {
		return InvalidEventArgument(argName)
	}

	var err error
	// syscall filters are special in that they take a string input such as:
	// task_rename.syscall=execve,execveat
	// but their internal filter values are numerical, as such they get a special
	// parsing case.
	if argName == "syscall" {
		err = filter.parseSyscallFilter(id, operatorAndValues)
	} else {
		err = filter.parseFilter(id, argName, operatorAndValues, func() Filter {
			// TODO: map argument type to an appropriate filter constructor
			return NewStringFilter()
		})
	}
	if err != nil {
		return err
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
		return err
	}

	// store the arg filter again
	filter.filters[id][argName] = argFilter

	return nil
}

// parseSyscallFilter is a specialized parser for syscall filters.
func (filter *ArgFilter) parseSyscallFilter(id events.ID, operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return InvalidExpression(operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return InvalidExpression(operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	syscalls := strings.Split(valuesString, ",")

	if _, ok := filter.filters[id]; !ok {
		filter.filters[id] = map[string]Filter{}
	}

	if _, ok := filter.filters[id]["syscall"]; !ok {
		// store new event arg filter if missing
		argFilter := NewInt32Filter()
		filter.filters[id]["syscall"] = argFilter
	}

	syscallFilter := filter.filters[id]["syscall"]
	for _, syscall := range syscalls {
		id, ok := events.Definitions.GetID(syscall)
		if !ok {
			return InvalidValue(syscall)
		}
		def := events.Definitions.Get(id)
		if !def.Syscall {
			return InvalidValue(syscall)
		}
		syscallFilter.Parse(fmt.Sprintf("%s%d", operatorString, id))
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
