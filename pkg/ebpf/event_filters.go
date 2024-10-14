package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type eventFilterHandler func(t *Tracee, eventFilters []map[string]filters.Filter[*filters.StringFilter]) error

var eventFilterHandlers = map[events.ID]eventFilterHandler{}

// handleEventFilters performs eBPF related actions according to event filters.
// For example, an event can use one of its filters to populate eBPF maps, or perhaps
// attach eBPF programs according to the filters.
func (t *Tracee) handleEventFilters() error {
	// Iterate through registerd event filter handlers
	for eventID, handler := range eventFilterHandlers {
		// Make sure this event is selected
		if _, err := t.eventsDependencies.GetEvent(eventID); err != nil {
			continue
		}

		// Construct filters for this event
		eventFilters := make([]map[string]filters.Filter[*filters.StringFilter], 0)
		for iterator := t.policyManager.CreateAllIterator(); iterator.HasNext(); {
			policy := iterator.Next()
			policyFilters := policy.DataFilter.GetEventFilters(eventID)
			if len(policyFilters) == 0 {
				continue
			}
			eventFilters = append(eventFilters, policyFilters)
		}
		if len(eventFilters) == 0 {
			// No filters for this event
			continue
		}

		// Call handler
		if err := handler(t, eventFilters); err != nil {
			if err := t.eventsDependencies.RemoveEvent(eventID); err != nil {
				logger.Warnw("Failed to remove event from dependencies manager", "remove reason", "failed handling event filters", "error", err)
			}
			return fmt.Errorf("failed to handle filters for event %s: %v", events.Core.GetDefinitionByID(eventID).GetName(), err)
		}
	}

	return nil
}
