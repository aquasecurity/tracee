package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

type ArgFilter struct {
	Filters map[events.ID]map[string]StringFilter // key to the first map is event id, and to the second map the argument name
	Enabled bool
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
		filter.Filters[id] = make(map[string]StringFilter)
	}

	if _, ok := filter.Filters[id][argName]; !ok {
		filter.Filters[id][argName] = StringFilter{}
	}

	val := filter.Filters[id][argName]

	val.Equal = append(val.Equal, strFilter.Equal...)
	val.NotEqual = append(val.NotEqual, strFilter.NotEqual...)

	filter.Filters[id][argName] = val

	return nil
}
