package policy

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type Policies struct {
	rwmu sync.RWMutex

	policiesArray             [MaxPolicies]*Policy // underlying filter policies array
	filterEnabledPoliciesMap  map[*Policy]int      // stores only enabled policies
	filterUserlandPoliciesMap map[*Policy]int      // stores a reduced map with only userland filterable policies

	uidFilterMin            uint64
	uidFilterMax            uint64
	pidFilterMin            uint64
	pidFilterMax            uint64
	uidFilterableInUserland bool
	pidFilterableInUserland bool

	filterableInUserland    uint64 // bitmap of policies that must be filtered in userland
	containerFiltersEnabled uint64 // bitmap of policies that have at least one container filter type enabled
}

func NewPolicies() *Policies {
	return &Policies{
		rwmu:                      sync.RWMutex{},
		policiesArray:             [MaxPolicies]*Policy{},
		filterEnabledPoliciesMap:  map[*Policy]int{},
		filterUserlandPoliciesMap: map[*Policy]int{},
		uidFilterMin:              filters.MinNotSetUInt,
		uidFilterMax:              filters.MaxNotSetUInt,
		pidFilterMin:              filters.MinNotSetUInt,
		pidFilterMax:              filters.MaxNotSetUInt,
		uidFilterableInUserland:   false,
		pidFilterableInUserland:   false,
		filterableInUserland:      0,
		containerFiltersEnabled:   0,
	}
}

func (ps *Policies) Count() int {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return len(ps.filterEnabledPoliciesMap)
}

func (ps *Policies) UIDFilterMin() uint64 {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.uidFilterMin
}

func (ps *Policies) UIDFilterMax() uint64 {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.uidFilterMax
}

func (ps *Policies) PIDFilterMin() uint64 {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.pidFilterMin
}

func (ps *Policies) PIDFilterMax() uint64 {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.pidFilterMax
}

func (ps *Policies) UIDFilterableInUserland() bool {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.uidFilterableInUserland
}

func (ps *Policies) PIDFilterableInUserland() bool {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.pidFilterableInUserland
}

// ContainerFilterEnabled returns a bitmap of policies that have at least
// one container filter type enabled.
func (ps *Policies) ContainerFilterEnabled() uint64 {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.containerFiltersEnabled
}

// FilterableInUserland returns a bitmap of policies that must be filtered in userland
// (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
func (ps *Policies) FilterableInUserland() uint64 {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.filterableInUserland
}

// Compute recalculates values, updates flags, fills the reduced userland map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at initialization and at every runtime policies changes.
// func (ps *Policies) Compute() {
// 	ps.WriteLock()
// 	defer ps.WriteUnlock()

// 	compute(ps)
// }

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

	ps.compute()

	return nil
}

// Add adds a policy to Policies, setting its ID to the first available slot.
// Returns error if policy is nil or there are no available slots.
// Returns nil if already set with the same ID.
func (ps *Policies) Add(p *Policy) error {
	ps.WriteLock()
	defer ps.WriteUnlock()

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

// Set sets a policy to Policies.
// Returns error if policy is nil or ID is out of range.
// Returns nil if already set with the same ID.
func (ps *Policies) Set(p *Policy) error {
	ps.WriteLock()
	defer ps.WriteUnlock()

	return ps.set(p.ID, p)
}

// Delete deletes a policy from Policies.
func (ps *Policies) Delete(id int) error {
	ps.WriteLock()
	defer ps.WriteUnlock()

	if !isIDInRange(id) {
		return PoliciesOutOfRangeError(id)
	}
	if len(ps.filterEnabledPoliciesMap) == 0 {
		return nil
	}

	delete(ps.filterEnabledPoliciesMap, ps.policiesArray[id])
	delete(ps.filterUserlandPoliciesMap, ps.policiesArray[id])
	ps.policiesArray[id] = nil

	ps.compute()

	return nil
}

// Lookup returns a policy by ID.
//
// Despite being thread-safe, as it returns a pointer, the policy may be changed
// by other threads at the time the caller uses it.
func (ps *Policies) Lookup(id int) (*Policy, error) {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

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
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	names := []string{}

	for p := range ps.filterEnabledPoliciesMap {
		if utils.HasBit(matched, uint(p.ID)) {
			names = append(names, p.Name)
		}
	}

	return names
}

// Map returns map with all policies.
//
// This map is not a copy, so it should only be used for read operations and
// surrounded by a read lock. See Policies.ReadLock() and Policies.ReadUnlock().
func (ps *Policies) Map() map[*Policy]int {
	return ps.filterEnabledPoliciesMap
}

// FilterableInUserlandMap returns a reduced policies map which must be filtered in
// userland (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
//
// This map is not a copy, so it should only be used for read operations and
// surrounded by a read lock. See Policies.ReadLock() and Policies.ReadUnlock().
func (ps *Policies) FilterableInUserlandMap() map[*Policy]int {
	return ps.filterUserlandPoliciesMap
}

func (ps *Policies) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for p := range ps.filterEnabledPoliciesMap {
		if p.containerFilterEnabled() {
			utils.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// calculateGlobalMinMax sets the global min and max, to be checked in kernel,
// of the Minimum and Maximum enabled filters only if context filter types
// (e.g. BPFUIDFilter) from all policies have both Minimum and Maximum values set.
//
// Policies userland filter flags are also set (e.g.
// uidFilterableInUserland).
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

		uidMinFilterableInUserland bool
		uidMaxFilterableInUserland bool
		pidMinFilterableInUserland bool
		pidMaxFilterableInUserland bool
	)

	for p := range ps.filterEnabledPoliciesMap {
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
	for p := range ps.filterEnabledPoliciesMap {
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

func (ps *Policies) WriteLock() {
	ps.rwmu.Lock()
}

func (ps *Policies) WriteUnlock() {
	ps.rwmu.Unlock()
}

func (ps *Policies) ReadLock() {
	ps.rwmu.RLock()
}

func (ps *Policies) ReadUnlock() {
	ps.rwmu.RUnlock()
}

const MaxPolicies = 64

func isIDInRange(id int) bool {
	return id >= 0 && id < MaxPolicies
}

// compute recalculates values, updates flags, fills the reduced userland map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at every runtime policies changes.
func (ps *Policies) compute() {
	ps.calculateGlobalMinMax()

	ps.updateContainerFilterEnabled()

	userlandMap := make(map[*Policy]int)
	ps.filterableInUserland = 0
	for p := range ps.filterEnabledPoliciesMap {
		if p.ArgFilter.Enabled() ||
			p.RetFilter.Enabled() ||
			p.ContextFilter.Enabled() ||
			(p.UIDFilter.Enabled() && ps.UIDFilterableInUserland()) ||
			(p.PIDFilter.Enabled() && ps.PIDFilterableInUserland()) {
			// add policy and set the related bit
			userlandMap[p] = p.ID
			utils.SetBit(&ps.filterableInUserland, uint(p.ID))
		}
	}

	ps.filterUserlandPoliciesMap = userlandMap
}
