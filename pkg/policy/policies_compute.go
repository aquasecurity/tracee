package policy

import (
	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// compute recalculates values, updates flags, fills the reduced userland map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at every runtime policies changes.
func (ps *policies) compute() {
	ps.calculateGlobalMinMax()
	ps.updateContainerFilterEnabled()
	ps.updateUserlandPolicies()
}

// calculateGlobalMinMax sets the global min and max, to be checked in kernel,
// of the Minimum and Maximum enabled filters only if scope filter types
// (e.g. BPFUIDFilter) from all policies have both Minimum and Maximum values set.
//
// Policies userland filter flags are also set (e.g. uidFilterableInUserland).
//
// The scope filter types relevant for this function are just UIDFilter and
// PIDFilter.
func (ps *policies) calculateGlobalMinMax() {
	var (
		uidMinFilterCount int
		uidMaxFilterCount int
		uidFilterCount    int
		pidMinFilterCount int
		pidMaxFilterCount int
		pidFilterCount    int
		policyCount       int

		uidMinFilterableInUserland bool
		uidMaxFilterableInUserland bool
		pidMinFilterableInUserland bool
		pidMaxFilterableInUserland bool
	)

	for _, p := range ps.allFromMap() {
		policyCount++

		if p.UIDFilter.Enabled() {
			uidFilterCount++

			if p.UIDFilter.Minimum() != filters.GetUnsetMin[uint32]() {
				uidMinFilterCount++
			}
			if p.UIDFilter.Maximum() != filters.GetUnsetMax[uint32]() {
				uidMaxFilterCount++
			}
		}
		if p.PIDFilter.Enabled() {
			pidFilterCount++

			if p.PIDFilter.Minimum() != filters.GetUnsetMin[uint32]() {
				pidMinFilterCount++
			}
			if p.PIDFilter.Maximum() != filters.GetUnsetMax[uint32]() {
				pidMaxFilterCount++
			}
		}
	}

	uidMinFilterableInUserland = policyCount > 1 && (uidMinFilterCount != uidFilterCount)
	uidMaxFilterableInUserland = policyCount > 1 && (uidMaxFilterCount != uidFilterCount)
	pidMinFilterableInUserland = policyCount > 1 && (pidMinFilterCount != pidFilterCount)
	pidMaxFilterableInUserland = policyCount > 1 && (pidMaxFilterCount != pidFilterCount)

	// reset global min max
	ps.uidFilterMax = filters.GetUnsetMax[uint64]()
	ps.uidFilterMin = filters.GetUnsetMin[uint64]()
	ps.pidFilterMax = filters.GetUnsetMax[uint64]()
	ps.pidFilterMin = filters.GetUnsetMin[uint64]()

	ps.uidFilterableInUserland = uidMinFilterableInUserland || uidMaxFilterableInUserland
	ps.pidFilterableInUserland = pidMinFilterableInUserland || pidMaxFilterableInUserland

	if ps.uidFilterableInUserland && ps.pidFilterableInUserland {
		// there's no need to iterate filter policies again since
		// all uint events will be submitted from ebpf with no regards

		return
	}

	// set a reduced range of uint values to be filtered in ebpf
	for _, p := range ps.allFromMap() {
		if p.UIDFilter.Enabled() {
			if !uidMinFilterableInUserland && p.UIDFilter.Minimum() != filters.GetUnsetMin[uint32]() {
				if ps.uidFilterMin > uint64(p.UIDFilter.Minimum()) {
					ps.uidFilterMin = uint64(p.UIDFilter.Minimum())
				}
			}
			if !uidMaxFilterableInUserland && p.UIDFilter.Maximum() != filters.GetUnsetMax[uint32]() {
				if ps.uidFilterMax < uint64(p.UIDFilter.Maximum()) {
					ps.uidFilterMax = uint64(p.UIDFilter.Maximum())
				}
			}
		}
		if p.PIDFilter.Enabled() {
			if !pidMinFilterableInUserland && p.PIDFilter.Minimum() != filters.GetUnsetMin[uint32]() {
				if ps.pidFilterMin > uint64(p.PIDFilter.Minimum()) {
					ps.pidFilterMin = uint64(p.PIDFilter.Minimum())
				}
			}
			if !pidMaxFilterableInUserland && p.PIDFilter.Maximum() != filters.GetUnsetMax[uint32]() {
				if ps.pidFilterMax < uint64(p.PIDFilter.Maximum()) {
					ps.pidFilterMax = uint64(p.PIDFilter.Maximum())
				}
			}
		}
	}
}

func (ps *policies) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for _, p := range ps.allFromMap() {
		if p.ContainerFilterEnabled() {
			bitwise.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// updateUserlandPolicies sets the userlandPolicies list and the filterableInUserland bitmap.
func (ps *policies) updateUserlandPolicies() {
	userlandList := []*Policy{}
	ps.filterableInUserland = false

	for _, p := range ps.allFromArray() {
		if p == nil {
			continue
		}

		hasUserlandFilters := false

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
		if hasUserlandFilters ||
			(p.UIDFilter.Enabled() && ps.uidFilterableInUserland) ||
			(p.PIDFilter.Enabled() && ps.pidFilterableInUserland) {
			// add policy to userland list and set the flag
			userlandList = append(userlandList, p)
			ps.filterableInUserland = true
		}
	}

	ps.userlandPolicies = userlandList
}
