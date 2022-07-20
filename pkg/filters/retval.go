package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

type RetFilter struct {
	Filters map[events.ID]IntFilter
	Enabled bool
}

func (filter *RetFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	filter.Enabled = true
	// Ret filter has the following format: "event.ret=val"
	// filterName have the format event.retval, and operatorAndValues have the format "=val"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 || splitFilter[1] != "retval" {
		return fmt.Errorf("invalid retval filter format %s%s", filterName, operatorAndValues)
	}
	eventName := splitFilter[0]

	id, ok := eventsNameToID[eventName]
	if !ok {
		return fmt.Errorf("invalid retval filter event name: %s", eventName)
	}

	if _, ok := filter.Filters[id]; !ok {
		filter.Filters[id] = IntFilter{
			Equal:    []int64{},
			NotEqual: []int64{},
			Less:     LessNotSetInt,
			Greater:  GreaterNotSetInt,
		}
	}

	intFilter := filter.Filters[id]

	// Treat operatorAndValues as an int filter to avoid code duplication
	err := (&intFilter).Parse(operatorAndValues)
	if err != nil {
		return err
	}

	filter.Filters[id] = intFilter

	return nil
}
