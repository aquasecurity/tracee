package detectors

import (
	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// applyScopeFilters applies scope filter to an event
// Returns true if the event passes the filter (or if filter is nil)
func applyScopeFilters(event *v1beta1.Event, scopeFilter *filters.ScopeFilter) bool {
	if scopeFilter == nil || !scopeFilter.Enabled() {
		return true // No filter = match all
	}

	// Convert v1beta1.Event to trace.Event for filter compatibility
	// TODO: remove this conversion once the filter API is updated
	traceEvent := events.ConvertFromProto(event)
	return scopeFilter.Filter(*traceEvent)
}
