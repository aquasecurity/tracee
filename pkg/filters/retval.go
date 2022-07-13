package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/protocol"
)

type RetFilter struct {
	Filters map[events.ID]*IntFilter
	enabled bool
}

func (filter *RetFilter) Enable() {
	filter.enabled = true
	for _, f := range filter.Filters {
		f.Enable()
	}
}

func (filter *RetFilter) Disable() {
	filter.enabled = false
	for _, f := range filter.Filters {
		f.Disable()
	}
}

func (filter *RetFilter) Enabled() bool {
	return filter.enabled
}

func (filter *RetFilter) Filter(eventID events.ID, retval int64) bool {
	if !filter.enabled {
		return true
	}
	if filter, ok := filter.Filters[eventID]; ok {
		if !filter.Filter(retval) {
			return false
		}
	}
	return true
}

func (filter *RetFilter) Add(filterReq protocol.Filter) error {
	field := filterReq.Field
	parts := strings.Split(field, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid retval filter format: %s", field)
	}
	eventName := parts[0]

	id, ok := events.Definitions.GetID(eventName)
	if !ok {
		return fmt.Errorf("invalid retval filter event name: %s", eventName)
	}
	eventFilter := filter.Filters[id]
	if eventFilter == nil {
		eventFilter = NewIntFilter()
	}

	err := eventFilter.Add(filterReq)
	if err != nil {
		return fmt.Errorf("failed to set ret filter: %s", err)
	}
	return nil
}
