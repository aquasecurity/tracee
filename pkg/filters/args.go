package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type ArgFilter struct {
	Filters map[events.ID]map[string]*StringFilter // key to the first map is event id, and to the second map the argument name
	Enabled bool
}

func NewArgFilter() *ArgFilter {
	return &ArgFilter{
		Filters: map[events.ID]map[string]*StringFilter{},
		Enabled: false,
	}
}

func matchFilter(filters []string, argValStr string) bool {
	for _, f := range filters {
		prefixCheck := f[len(f)-1] == '*'
		if prefixCheck {
			f = f[0 : len(f)-1]
		}
		suffixCheck := f[0] == '*'
		if suffixCheck {
			f = f[1:]
		}
		if argValStr == f ||
			(prefixCheck && !suffixCheck && strings.HasPrefix(argValStr, f)) ||
			(suffixCheck && !prefixCheck && strings.HasSuffix(argValStr, f)) ||
			(prefixCheck && suffixCheck && strings.Contains(argValStr, f)) {
			return true
		}
	}
	return false
}

func (filter *ArgFilter) Filter(eventID events.ID, args []trace.Argument) bool {
	if filter.Enabled {
		for argName, filter := range filter.Filters[events.ID(eventID)] {
			var argVal interface{}
			ok := false
			for _, arg := range args {
				if arg.Name == argName {
					argVal = arg.Value
					ok = true
				}
			}
			if !ok {
				continue
			}
			// TODO: use type assertion instead of string conversion
			argValStr := fmt.Sprint(argVal)
			match := matchFilter(filter.Equal, argValStr)
			if !match && len(filter.Equal) > 0 {
				return false
			}
			matchExclude := matchFilter(filter.NotEqual, argValStr)
			if matchExclude {
				return false
			}
		}
	}
	return true
}

func (filter *ArgFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	filter.Enabled = true
	// Event argument filter has the following format: "event.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 {
		return fmt.Errorf("invalid argument filter format %s%s", filterName, operatorAndValues)
	}
	eventName := splitFilter[0]
	argName := splitFilter[1]

	id, ok := eventsNameToID[eventName]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

	eventDefinition, ok := events.Definitions.GetSafe(id)
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
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
		return fmt.Errorf("invalid argument filter argument name: %s", argName)
	}

	strFilter := &StringFilter{
		Equal:    []string{},
		NotEqual: []string{},
	}

	// Treat operatorAndValues as a string filter to avoid code duplication
	err := strFilter.Parse(operatorAndValues)
	if err != nil {
		return err
	}

	if _, ok := filter.Filters[id]; !ok {
		filter.Filters[id] = map[string]*StringFilter{}
	}

	if _, ok := filter.Filters[id][argName]; !ok {
		filter.Filters[id][argName] = &StringFilter{}
	}

	val := filter.Filters[id][argName]

	val.Equal = append(val.Equal, strFilter.Equal...)
	val.NotEqual = append(val.NotEqual, strFilter.NotEqual...)

	filter.Filters[id][argName] = val

	return nil
}
