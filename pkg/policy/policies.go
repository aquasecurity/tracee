package policy

import (
	"sync/atomic"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// TODO: add locking mechanism as policies will change at runtime
type Policies struct {
	policiesArray              [MaxPolicies]*Policy // underlying filter policies array
	filterEnabledPoliciesMap   map[*Policy]int      // stores only enabled policies
	filterUserSpacePoliciesMap map[*Policy]int      // stores a reduced map with only user space filtered policies

	uidFilterMin             uint64
	uidFilterMax             uint64
	pidFilterMin             uint64
	pidFilterMax             uint64
	uidFilterableInUserSpace bool
	pidFilterableInUserSpace bool

	filterableInUserSpace   uint64 // bitmap of policies that must be filtered in user space
	containerFiltersEnabled uint64 // bitmap of policies that have at least one container filter type enabled
}

func NewPolicies() *Policies {
	return &Policies{
		policiesArray:              [MaxPolicies]*Policy{},
		filterEnabledPoliciesMap:   map[*Policy]int{},
		filterUserSpacePoliciesMap: map[*Policy]int{},
		uidFilterMin:               filters.MinNotSetUInt,
		uidFilterMax:               filters.MaxNotSetUInt,
		pidFilterMin:               filters.MinNotSetUInt,
		pidFilterMax:               filters.MaxNotSetUInt,
		uidFilterableInUserSpace:   false,
		pidFilterableInUserSpace:   false,
		filterableInUserSpace:      0,
		containerFiltersEnabled:    0,
	}
}

func (ps *Policies) Count() int {
	return len(ps.filterEnabledPoliciesMap)
}

func (ps *Policies) UIDFilterMin() uint64 {
	return ps.uidFilterMin
}

func (ps *Policies) UIDFilterMax() uint64 {
	return ps.uidFilterMax
}

func (ps *Policies) PIDFilterMin() uint64 {
	return ps.pidFilterMin
}

func (ps *Policies) PIDFilterMax() uint64 {
	return ps.pidFilterMax
}

func (ps *Policies) UIDFilterableInUserSpace() bool {
	return ps.uidFilterableInUserSpace
}

func (ps *Policies) PIDFilterableInUserSpace() bool {
	return ps.pidFilterableInUserSpace
}

// ContainerFilterEnabled returns a bitmap of policies that have at least
// one container filter type enabled.
//
// TODO: make sure the stores are also atomic (an atomic load is only protecting
// the read from context switches, not from CPU cache coherency issues).
func (ps *Policies) ContainerFilterEnabled() uint64 {
	return atomic.LoadUint64(&ps.containerFiltersEnabled)
}

// FilterableInUserSpace returns a bitmap of policies that must be filtered in user space
// (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
//
// TODO: make sure the stores are also atomic (an atomic load is only protecting
// the read from context switches, not from CPU cache coherency issues).
func (ps *Policies) FilterableInUserSpace() uint64 {
	return atomic.LoadUint64(&ps.filterableInUserSpace)
}

// Compute recalculates values, updates flags, fills the reduced user space map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at initialization and at every runtime policies changes.
func (ps *Policies) Compute() {
	// update global min and max
	ps.calculateGlobalMinMax()

	// update enabled container filter flag
	ps.updateContainerFilterEnabled()

	userSpaceMap := make(map[*Policy]int)
	ps.filterableInUserSpace = 0
	for p := range ps.filterEnabledPoliciesMap {
		if p.ArgFilter.Enabled() ||
			p.RetFilter.Enabled() ||
			p.ContextFilter.Enabled() ||
			(p.UIDFilter.Enabled() && ps.UIDFilterableInUserSpace()) ||
			(p.PIDFilter.Enabled() && ps.PIDFilterableInUserSpace()) {
			// add policy and set the related bit
			userSpaceMap[p] = p.ID
			utils.SetBit(&ps.filterableInUserSpace, uint(p.ID))
		}
	}

	ps.filterUserSpacePoliciesMap = userSpaceMap
}

// set, if not err, always reassign values
func (ps *Policies) set(id int, p *Policy) error {
	if p == nil {
		return PolicyNilError()
	}
	if !isIDInRange(id) {
		return PoliciesOutOfRangeError(id)
	}
	if _, found := ps.filterEnabledPoliciesMap[p]; found {
		if p.ID != id {
			return PolicyAlreadyExists(p, id)
		}
	}

	p.ID = id
	ps.policiesArray[id] = p
	ps.filterEnabledPoliciesMap[p] = id

	ps.Compute()

	return nil
}

// Add adds a policy to Policies.
// Its ID (index) is set to the first room found.
// Returns nil if policy is already inserted.
func (ps *Policies) Add(p *Policy) error {
	if len(ps.filterEnabledPoliciesMap) == MaxPolicies {
		return PoliciesMaxExceededError()
	}

	for id := range ps.policiesArray {
		if ps.policiesArray[id] == nil {
			return ps.set(id, p)
		}
	}

	return nil
}

func (ps *Policies) Set(p *Policy) error {
	return ps.set(p.ID, p)
}

// Delete deletes a policy from Policies.
func (ps *Policies) Delete(id int) error {
	if !isIDInRange(id) {
		return PoliciesOutOfRangeError(id)
	}
	if len(ps.filterEnabledPoliciesMap) == 0 {
		return nil
	}

	delete(ps.filterEnabledPoliciesMap, ps.policiesArray[id])
	delete(ps.filterUserSpacePoliciesMap, ps.policiesArray[id])
	ps.policiesArray[id] = nil

	ps.Compute()

	return nil
}

func (ps *Policies) Lookup(id int) (*Policy, error) {
	if !isIDInRange(id) {
		return nil, PoliciesOutOfRangeError(id)
	}

	p := ps.policiesArray[id]
	if p == nil {
		return nil, PolicyNotFoundError(id)
	}
	return p, nil
}

// MatchedNames returns a list of matched policies names based on
// the given matched bitmap.
func (ps *Policies) MatchedNames(matched uint64) []string {
	names := []string{}

	for p := range ps.Map() {
		if utils.HasBit(matched, uint(p.ID)) {
			names = append(names, p.Name)
		}
	}

	return names
}

// Map returns map with all policies.
func (ps *Policies) Map() map[*Policy]int {
	return ps.filterEnabledPoliciesMap
}

// FilterableInUserSpaceMap returns a reduced policies map which must be filtered in
// user space (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
func (ps *Policies) FilterableInUserSpaceMap() map[*Policy]int {
	return ps.filterUserSpacePoliciesMap
}

func (ps *Policies) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for p := range ps.Map() {
		if p.ContainerFilterEnabled() {
			utils.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// calculateGlobalMinMax sets the global min and max, to be checked in kernel
// space, of the Minimum and Maximum enabled filters only if context filter
// types (e.g. BPFUIDFilter) from all policies have both Minimum and Maximum
// values set.
//
// Policies user space filter flags are also set (e.g.
// uidFilterableInUserSpace).
//
// The context filter types relevant for this function are just UIDFilter and
// PIDFilter.
func (ps *Policies) calculateGlobalMinMax() {
	var (
		uidMinFilterCount int
		uidMaxFilterCount int
		uidFilterCount    int
		pidMinFilterCount int
		pidMaxFilterCount int
		pidFilterCount    int
		policyCount       int

		uidMinFilterableInUserSpace bool
		uidMaxFilterableInUserSpace bool
		pidMinFilterableInUserSpace bool
		pidMaxFilterableInUserSpace bool
	)

	for p := range ps.Map() {
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

	uidMinFilterableInUserSpace = policyCount > 1 && (uidMinFilterCount != uidFilterCount)
	uidMaxFilterableInUserSpace = policyCount > 1 && (uidMaxFilterCount != uidFilterCount)
	pidMinFilterableInUserSpace = policyCount > 1 && (pidMinFilterCount != pidFilterCount)
	pidMaxFilterableInUserSpace = policyCount > 1 && (pidMaxFilterCount != pidFilterCount)

	// reset global min max
	ps.uidFilterMax = filters.MaxNotSetUInt
	ps.uidFilterMin = filters.MinNotSetUInt
	ps.pidFilterMax = filters.MaxNotSetUInt
	ps.pidFilterMin = filters.MinNotSetUInt

	ps.uidFilterableInUserSpace = uidMinFilterableInUserSpace || uidMaxFilterableInUserSpace
	ps.pidFilterableInUserSpace = pidMinFilterableInUserSpace || pidMaxFilterableInUserSpace

	if ps.UIDFilterableInUserSpace() && ps.PIDFilterableInUserSpace() {
		// there's no need to iterate filter policies again since
		// all uint events will be submitted from ebpf with no regards

		return
	}

	// set a reduced range of uint values to be filtered in ebpf
	for p := range ps.filterEnabledPoliciesMap {
		if p.UIDFilter.Enabled() {
			if !uidMinFilterableInUserSpace {
				ps.uidFilterMin = utils.Min(ps.uidFilterMin, p.UIDFilter.Minimum())
			}
			if !uidMaxFilterableInUserSpace {
				ps.uidFilterMax = utils.Max(ps.uidFilterMax, p.UIDFilter.Maximum())
			}
		}
		if p.PIDFilter.Enabled() {
			if !pidMinFilterableInUserSpace {
				ps.pidFilterMin = utils.Min(ps.pidFilterMin, p.PIDFilter.Minimum())
			}
			if !pidMaxFilterableInUserSpace {
				ps.pidFilterMax = utils.Max(ps.pidFilterMax, p.PIDFilter.Maximum())
			}
		}
	}
}

// ContainerFilterEnabled returns true when the policy has at least one container filter type enabled
func (ps *Policy) ContainerFilterEnabled() bool {
	return (ps.ContFilter.Enabled() && ps.ContFilter.Value()) ||
		(ps.NewContFilter.Enabled() && ps.NewContFilter.Value()) ||
		ps.ContIDFilter.Enabled()
}
