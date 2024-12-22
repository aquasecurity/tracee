package policy

import (
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// compute recalculates values, updates flags, fills the reduced userland map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at every runtime policies changes.
func (ps *policies) compute() {
	ps.updateContainerFilterEnabled()
	ps.updateUserlandRules()
}

func (ps *policies) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for _, p := range ps.allFromMap() {
		if p.ContainerFilterEnabled() {
			utils.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// updateUserlandRules sets the userlandRules list.
func (ps *policies) updateUserlandRules() {
	userlandList := []*Policy{}

	for _, p := range ps.allFromMap() {
		if p == nil {
			continue
		}

		hasUserlandFilters := false
		uidFilterableInUserland := false
		pidFilterableInUserland := false

		if p.UIDFilter.Enabled() &&
			((p.UIDFilter.Minimum() != filters.MinNotSetUInt) ||
				(p.UIDFilter.Maximum() != filters.MaxNotSetUInt)) {
			uidFilterableInUserland = true
		}

		if p.PIDFilter.Enabled() &&
			((p.PIDFilter.Minimum() != filters.MinNotSetUInt) ||
				(p.PIDFilter.Maximum() != filters.MaxNotSetUInt)) {
			pidFilterableInUserland = true
		}

		// Check filters under Rules
		for _, rule := range p.Rules {
			if rule.DataFilter.Enabled() ||
				rule.RetFilter.Enabled() ||
				rule.ScopeFilter.Enabled() {
				hasUserlandFilters = true
				break
			}
		}

		// Check other filters
		if hasUserlandFilters || uidFilterableInUserland || pidFilterableInUserland {
			// add policy to userland list
			userlandList = append(userlandList, p)
		}
	}

	ps.userlandRules = userlandList
}
