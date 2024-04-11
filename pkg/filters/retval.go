package filters

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type RetFilter struct {
	filters map[events.ID]*IntFilter[int64]
	enabled bool
}

// Compile-time check to ensure that RetFilter implements the Cloner interface
var _ utils.Cloner[*RetFilter] = &RetFilter{}

func NewRetFilter() *RetFilter {
	return &RetFilter{
		filters: map[events.ID]*IntFilter[int64]{},
		enabled: false,
	}
}

func (filter *RetFilter) Filter(eventID events.ID, retVal int64) bool {
	if !filter.Enabled() {
		return true
	}
	if filter, ok := filter.filters[eventID]; ok {
		return filter.Filter(retVal)
	}
	return true
}

func (filter *RetFilter) Enable() {
	filter.enabled = true
	for _, f := range filter.filters {
		f.Enable()
	}
}

func (filter *RetFilter) Disable() {
	filter.enabled = false
	for _, f := range filter.filters {
		f.Disable()
	}
}

func (filter *RetFilter) Enabled() bool {
	return filter.enabled
}

func (filter *RetFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	// Ret filter has the following format: "event.retval=val"
	// filterName have the format event.retval, and operatorAndValues have the format "=val"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 || splitFilter[1] != "retval" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	eventName := splitFilter[0]
	if eventName == "" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	id, ok := eventsNameToID[eventName]
	if !ok {
		return InvalidEventName(eventName)
	}

	if _, ok := filter.filters[id]; !ok {
		filter.filters[id] = NewIntFilter()
	}

	intFilter := filter.filters[id]

	// Treat operatorAndValues as an int filter to avoid code duplication
	err := intFilter.Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	filter.filters[id] = intFilter

	filter.Enable()

	return nil
}

func (filter *RetFilter) Clone() *RetFilter {
	if filter == nil {
		return nil
	}

	n := NewRetFilter()

	for k, v := range filter.filters {
		n.filters[k] = v.Clone()
	}
	n.enabled = filter.enabled

	return n
}
