package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

type RetFilter struct {
	Filters map[events.ID]*IntFilter
	Enabled bool
}

func NewRetFilter() *RetFilter {
	return &RetFilter{
		Filters: map[events.ID]*IntFilter{},
		Enabled: false,
	}
}

func (filter *RetFilter) Filter(eventID events.ID, retVal int64) bool {
	if filter.Enabled {
		if filter, ok := filter.Filters[eventID]; ok {
			match := false
			for _, f := range filter.Equal {
				if retVal == f {
					match = true
					break
				}
			}
			if !match && len(filter.Equal) > 0 {
				return false
			}
			for _, f := range filter.NotEqual {
				if retVal == f {
					return false
				}
			}
			if (filter.Greater != maxIntVal) && retVal <= filter.Greater {
				return false
			}
			if (filter.Less != minIntVal) && retVal >= filter.Less {
				return false
			}
		}
	}
	return true
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
		filter.Filters[id] = NewIntFilter()
	}

	intFilter := filter.Filters[id]

	// Treat operatorAndValues as an int filter to avoid code duplication
	err := intFilter.Parse(operatorAndValues)
	if err != nil {
		return err
	}

	filter.Filters[id] = intFilter

	return nil
}
