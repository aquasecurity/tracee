package filters

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
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
func (af *ArgFilter) GetEventFilters(eventID events.ID) map[string]Filter {
	return af.filters[eventID]
}

func (af *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if !af.Enabled() {
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

	for argName, f := range af.filters[eventID] {
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
		argVal = fmt.Sprint(argVal)

		res := f.Filter(argVal)
		if !res {
			return false
		}
	}

	return true
}

func (af *ArgFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
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

	if !events.Core.IsDefined(id) {
		return InvalidEventName(eventName)
	}
	eventDefinition := events.Core.GetDefinitionByID(id)
	eventParams := eventDefinition.GetParams()

	// check if argument name exists for this event
	argFound := false
	for i := range eventParams {
		if eventParams[i].Name == argName {
			argFound = true
			break
		}
	}

	// if the event is a signature event, we allow filtering on dynamic argument
	if !argFound && !eventDefinition.IsSignature() {
		return InvalidEventArgument(argName)
	}

	// valueHandler is passed to the filter constructor to allow for custom value handling
	// before the filter is applied
	valueHandler := func(val string) (string, error) {
		switch id {
		case events.SysEnter,
			events.SysExit:
			if argName == "syscall" { // handle either syscall name or syscall id
				_, err := strconv.Atoi(val)
				if err != nil {
					// if val is a syscall name, then we need to convert it to a syscall id
					syscallID, ok := events.Core.GetDefinitionIDByName(val)
					if !ok {
						return val, errfmt.Errorf("invalid syscall name: %s", val)
					}
					val = strconv.Itoa(int(syscallID))
				}
			}
		case events.HookedSyscall:
			if argName == "syscall" { // handle either syscall name or syscall id
				argEventID, err := strconv.Atoi(val)
				if err == nil {
					// if val is a syscall id, then we need to convert it to a syscall name
					val = events.Core.GetDefinitionByID(events.ID(argEventID)).GetName()
				}
			}
		}

		return val, nil
	}

	err := af.parseFilter(id, argName, operatorAndValues,
		func() Filter {
			// TODO: map argument type to an appropriate filter constructor
			return NewStringFilter(valueHandler)
		})
	if err != nil {
		return errfmt.WrapError(err)
	}

	af.Enable()

	return nil
}

// parseFilter adds an argument filter with the relevant filterConstructor
// The user must responsibly supply a reliable Filter object.
func (af *ArgFilter) parseFilter(id events.ID, argName string, operatorAndValues string, filterConstructor func() Filter) error {
	if _, ok := af.filters[id]; !ok {
		af.filters[id] = map[string]Filter{}
	}

	if _, ok := af.filters[id][argName]; !ok {
		// store new event arg filter if missing
		argFilter := filterConstructor()
		af.filters[id][argName] = argFilter
	}

	// extract the arg filter and parse expression into it
	f := af.filters[id][argName]
	err := f.Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// store the arg filter again
	af.filters[id][argName] = f

	return nil
}

func (af *ArgFilter) Enable() {
	af.enabled = true
	for _, filterMap := range af.filters {
		for _, f := range filterMap {
			f.Enable()
		}
	}
}

func (af *ArgFilter) Disable() {
	af.enabled = false
	for _, filterMap := range af.filters {
		for _, f := range filterMap {
			f.Disable()
		}
	}
}

func (af *ArgFilter) Enabled() bool {
	return af.enabled
}

func (af *ArgFilter) Clone() utils.Cloner {
	if af == nil {
		return nil
	}

	n := NewArgFilter()

	for eventID, filterMap := range af.filters {
		n.filters[eventID] = map[string]Filter{}
		for argName, f := range filterMap {
			n.filters[eventID][argName] = f.Clone().(Filter)
		}
	}

	n.enabled = af.enabled

	return n
}
