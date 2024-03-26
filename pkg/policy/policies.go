package policy

import (
	"sync"
	"sync/atomic"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	PolicyMax  = int(64)
	PolicyAll  = ^uint64(0)
	PolicyNone = uint64(0)
)

var (
	submitAllPolicies = newEventStates(
		eventStatesWithSubmit(PolicyAll),
	)
)

// TODO: refactor filterEnabledPoliciesMap and filterUserlandPoliciesMap
// maps to use int (Policy id) as key instead of *Policy.
// TODO: create a new map with policy name as key to speed up LookupByName()
type Policies struct {
	rwmu sync.RWMutex

	config                   config.PoliciesConfig
	version                  uint32                    // updated on snapshot store
	bpfInnerMaps             map[string]*bpf.BPFMapLow // BPF inner maps
	policiesArray            [PolicyMax]*Policy        // underlying filter policies array
	filterEnabledPoliciesMap map[*Policy]int           // stores only enabled policies

	// computed values
	evtsStates                *eventsStates
	filterUserlandPoliciesMap map[*Policy]int // stores a reduced map with only userland filterable policies
	uidFilterMin              uint64
	uidFilterMax              uint64
	pidFilterMin              uint64
	pidFilterMax              uint64
	uidFilterableInUserland   bool
	pidFilterableInUserland   bool
	filterableInUserland      uint64 // bitmap of policies that must be filtered in userland
	containerFiltersEnabled   uint64 // bitmap of policies that have at least one container filter type enabled
}

func NewPolicies(cfg config.PoliciesConfig) *Policies {
	return &Policies{
		rwmu:                      sync.RWMutex{},
		config:                    cfg,
		version:                   0,
		bpfInnerMaps:              map[string]*bpf.BPFMapLow{},
		policiesArray:             [PolicyMax]*Policy{},
		filterEnabledPoliciesMap:  map[*Policy]int{},
		evtsStates:                newEventsStates(),
		filterUserlandPoliciesMap: map[*Policy]int{},
		uidFilterMin:              filters.MinNotSetUInt,
		uidFilterMax:              filters.MaxNotSetUInt,
		pidFilterMin:              filters.MinNotSetUInt,
		pidFilterMax:              filters.MaxNotSetUInt,
		uidFilterableInUserland:   false,
		pidFilterableInUserland:   false,
		filterableInUserland:      PolicyNone,
		containerFiltersEnabled:   PolicyNone,
	}
}

// eventsStates returns the events states of Policies.
func (ps *Policies) eventsStates() *eventsStates {
	return ps.evtsStates
}

// EventsStates returns the events states of Policies.
func (ps *Policies) EventsStates() EventsStates {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.eventsStates()
}

func (ps *Policies) Count() int {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return len(ps.filterEnabledPoliciesMap)
}

func (ps *Policies) UIDFilterMin() uint64 {
	return atomic.LoadUint64(&ps.uidFilterMin)
}

func (ps *Policies) UIDFilterMax() uint64 {
	return atomic.LoadUint64(&ps.uidFilterMax)
}

func (ps *Policies) PIDFilterMin() uint64 {
	return atomic.LoadUint64(&ps.pidFilterMin)
}

func (ps *Policies) PIDFilterMax() uint64 {
	return atomic.LoadUint64(&ps.pidFilterMax)
}

func (ps *Policies) SetVersion(version uint16) {
	atomic.StoreUint32(&ps.version, uint32(version))
}

func (ps *Policies) Version() uint16 {
	return uint16(atomic.LoadUint32(&ps.version))
}

// WithContainerFilterEnabled returns a bitmap of policies representing the
// container filter types enabled.
func (ps *Policies) WithContainerFilterEnabled() uint64 {
	return atomic.LoadUint64(&ps.containerFiltersEnabled)
}

// ContainerFilterEnabled returns true if at least one policy has a
// container filter type enabled.
func (ps *Policies) ContainerFilterEnabled() bool {
	return ps.WithContainerFilterEnabled() > 0
}

// FilterableInUserland returns a bitmap of policies that must be filtered in userland
// (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
func (ps *Policies) FilterableInUserland() uint64 {
	return atomic.LoadUint64(&ps.filterableInUserland)
}

// compute recalculates values, updates flags, fills the reduced userland map,
// and sets the related bitmap that is used to prevent the iteration of the entire map.
//
// It must be called at initialization and at every runtime policies changes.
func (ps *Policies) compute() {
	// update global min and max
	ps.calculateGlobalMinMax()

	// update enabled container filter flag
	ps.updateContainerFilterEnabled()

	userlandMap := make(map[*Policy]int)
	ps.filterableInUserland = 0
	for p := range ps.filterEnabledPoliciesMap {
		if p.ArgFilter.Enabled() ||
			p.RetFilter.Enabled() ||
			p.ContextFilter.Enabled() ||
			(p.UIDFilter.Enabled() && ps.uidFilterableInUserland) ||
			(p.PIDFilter.Enabled() && ps.pidFilterableInUserland) {
			// add policy and set the related bit
			userlandMap[p] = p.ID
			utils.SetBit(&ps.filterableInUserland, uint(p.ID))
		}
	}

	ps.filterUserlandPoliciesMap = userlandMap
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

	ps.compute()

	return nil
}

// Add adds a policy to Policies.
// Its ID (index) is set to the first room found.
// Returns nil if policy is already inserted.
func (ps *Policies) Add(p *Policy) error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	if len(ps.filterEnabledPoliciesMap) == PolicyMax {
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
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	return ps.set(p.ID, p)
}

// Delete deletes a policy from Policies.
func (ps *Policies) Delete(id int) error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

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

// LookupById returns a policy by ID.
func (ps *Policies) LookupById(id int) (*Policy, error) {
	if !isIDInRange(id) {
		return nil, PoliciesOutOfRangeError(id)
	}

	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	p := ps.policiesArray[id]
	if p == nil {
		return nil, PolicyNotFoundByIDError(id)
	}
	return p, nil
}

// LookupByName returns a policy by name.
func (ps *Policies) LookupByName(name string) (*Policy, error) {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	for p := range ps.Map() {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, PolicyNotFoundByNameError(name)
}

// MatchedNames returns a list of matched policies names based on
// the given matched bitmap.
func (ps *Policies) MatchedNames(matched uint64) []string {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	names := []string{}

	for p := range ps.Map() {
		if utils.HasBit(matched, uint(p.ID)) {
			names = append(names, p.Name)
		}
	}

	return names
}

// Map returns map with all policies.
//
// It does not return a copy of the map, so it must be used only for iteration and
// after its snapshot has been stored, otherwise it may be in the initial state and
// not contain all policies computed.
func (ps *Policies) Map() map[*Policy]int {
	return ps.filterEnabledPoliciesMap
}

// FilterableInUserlandMap returns a reduced policies map which must be filtered in
// userland (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
//
// It does not return a copy of the map, so it must be used only for iteration and
// after its snapshot has been stored, otherwise it may be in the initial state and
// not contain all policies computed.
func (ps *Policies) FilterableInUserlandMap() map[*Policy]int {
	return ps.filterUserlandPoliciesMap
}

// TODO: Runtime API should encapsulate the following calls:
//
// 1. pols := policies.Clone() to get a clone before to apply changes
// 2. policy.Snapshots().Store(pols) to get the new version snapshot stored
// 3. tracee.populateFilterMaps(pols, true) to update the maps
// 4. and possibly other steps in which we iterate over the policies map

// Clone returns a deep copy of Policies.
func (ps *Policies) Clone() utils.Cloner {
	if ps == nil {
		return nil
	}

	nPols := NewPolicies(ps.config)

	// Deep copy of all policies
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()
	for _, p := range ps.policiesArray {
		if p == nil {
			continue
		}
		if err := nPols.Add(p.Clone().(*Policy)); err != nil {
			logger.Errorw("Cloning policy %s: %v", p.Name, err)
			return nil
		}
	}

	nPols.compute()

	return nPols
}

func (ps *Policies) updateContainerFilterEnabled() {
	ps.containerFiltersEnabled = 0

	for p := range ps.Map() {
		if p.ContainerFilterEnabled() {
			utils.SetBit(&ps.containerFiltersEnabled, uint(p.ID))
		}
	}
}

// calculateGlobalMinMax sets the global min and max, to be checked in kernel,
// of the Minimum and Maximum enabled filters only if context filter types
// (e.g. BPFUIDFilter) from all policies have both Minimum and Maximum values set.
//
// Policies userland filter flags are also set (e.g. uidFilterableInUserland).
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

func isIDInRange(id int) bool {
	return id >= 0 && id < PolicyMax
}
