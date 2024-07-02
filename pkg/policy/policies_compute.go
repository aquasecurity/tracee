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

			if p.UIDFilter.Minimum() != filters.MinNotSetUInt {
				uidMinFilterCount++
			}
			if p.UIDFilter.Maximum() != filters.MaxNotSetUInt {
				uidMaxFilterCount++
			}
		}
		if p.PIDFilter.Enabled() {
			pidFilterCount++

			if p.PIDFilter.Minimum() != filters.MinNotSetUInt {
				pidMinFilterCount++
			}
			if p.PIDFilter.Maximum() != filters.MaxNotSetUInt {
				pidMaxFilterCount++
			}
		}
	}

	uidMinFilterableInUserland = policyCount > 1 && (uidMinFilterCount != uidFilterCount)
	uidMaxFilterableInUserland = policyCount > 1 && (uidMaxFilterCount != uidFilterCount)
	pidMinFilterableInUserland = policyCount > 1 && (pidMinFilterCount != pidFilterCount)
	pidMaxFilterableInUserland = policyCount > 1 && (pidMaxFilterCount != pidFilterCount)

	// reset global min max
	ps.uidFilterMax = filters.MaxNotSetUInt
	ps.uidFilterMin = filters.MinNotSetUInt
	ps.pidFilterMax = filters.MaxNotSetUInt
	ps.pidFilterMin = filters.MinNotSetUInt

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
			if !uidMinFilterableInUserland {
				ps.uidFilterMin = utils.Min(ps.uidFilterMin, p.UIDFilter.Minimum())
			}
			if !uidMaxFilterableInUserland {
				ps.uidFilterMax = utils.Max(ps.uidFilterMax, p.UIDFilter.Maximum())
			}
		}
		if p.PIDFilter.Enabled() {
			if !pidMinFilterableInUserland {
				ps.pidFilterMin = utils.Min(ps.pidFilterMin, p.PIDFilter.Minimum())
			}
			if !pidMaxFilterableInUserland {
				ps.pidFilterMax = utils.Max(ps.pidFilterMax, p.PIDFilter.Maximum())
			}
		}
	}
}

func (ps *policies) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for _, p := range ps.allFromMap() {
		if p.ContainerFilterEnabled() {
			utils.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// updateUserlandPolicies sets the userlandPolicies list and the filterableInUserland bitmap.
func (ps *policies) updateUserlandPolicies() {
	userlandList := []*Policy{}
	ps.filterableInUserland = 0

	for _, p := range ps.allFromArray() {
		if p == nil {
			continue
		}

		if p.DataFilter.Enabled() ||
			p.RetFilter.Enabled() ||
			p.ScopeFilter.Enabled() ||
			(p.UIDFilter.Enabled() && ps.uidFilterableInUserland) ||
			(p.PIDFilter.Enabled() && ps.pidFilterableInUserland) {
			// add policy to userland list and set the respective bit
			userlandList = append(userlandList, p)
			utils.SetBit(&ps.filterableInUserland, uint(p.ID))
		}
	}

	ps.userlandPolicies = userlandList
}
