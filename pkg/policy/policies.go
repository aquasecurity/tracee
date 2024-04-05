package policy

import (
	"sync"
	"sync/atomic"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	MaxPolicies   int = 64
	AllPoliciesOn     = ^uint64(0)
)

var AlwaysSubmit = events.EventState{
	Submit: AllPoliciesOn,
}

type Policies struct {
	rwmu sync.RWMutex

	version           uint32                    // updated on snapshot store
	bpfInnerMaps      map[string]*bpf.BPFMapLow // BPF inner maps
	policiesArray     [MaxPolicies]*Policy      // underlying policies array for fast access of empty slots
	policiesMapByID   map[int]*Policy           // all policies map by ID
	policiesMapByName map[string]*Policy        // all policies map by name
	policiesList      []*Policy                 // all policies list

	// computed values

	userlandPolicies        []*Policy // reduced list with userland filterable policies (read in a hot path)
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
		rwmu:                    sync.RWMutex{},
		version:                 0,
		bpfInnerMaps:            map[string]*bpf.BPFMapLow{},
		policiesArray:           [MaxPolicies]*Policy{},
		policiesMapByID:         map[int]*Policy{},
		policiesMapByName:       map[string]*Policy{},
		policiesList:            []*Policy{},
		userlandPolicies:        []*Policy{},
		uidFilterMin:            filters.MinNotSetUInt,
		uidFilterMax:            filters.MaxNotSetUInt,
		pidFilterMin:            filters.MinNotSetUInt,
		pidFilterMax:            filters.MaxNotSetUInt,
		uidFilterableInUserland: false,
		pidFilterableInUserland: false,
		filterableInUserland:    0,
		containerFiltersEnabled: 0,
	}
}

func (ps *Policies) count() int {
	return len(ps.policiesMapByID)
}

func (ps *Policies) Count() int {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.count()
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

// ContainerFilterEnabled returns a bitmap of policies that have at least
// one container filter type enabled.
func (ps *Policies) ContainerFilterEnabled() uint64 {
	return atomic.LoadUint64(&ps.containerFiltersEnabled)
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

	userlandList := []*Policy{}
	ps.filterableInUserland = 0
	for _, p := range ps.policiesMapByID {
		if p.ArgFilter.Enabled() ||
			p.RetFilter.Enabled() ||
			p.ContextFilter.Enabled() ||
			(p.UIDFilter.Enabled() && ps.uidFilterableInUserland) ||
			(p.PIDFilter.Enabled() && ps.pidFilterableInUserland) {
			// add policy and set the related bit
			userlandList = append(userlandList, p)
			utils.SetBit(&ps.filterableInUserland, uint(p.ID))
		}
	}

	ps.userlandPolicies = userlandList
}

// set sets a policy at the given ID (index).
func (ps *Policies) set(id int, p *Policy) error {
	p.ID = id
	ps.policiesArray[id] = p
	ps.policiesMapByID[id] = p
	ps.policiesMapByName[p.Name] = p
	ps.policiesList = append(ps.policiesList, p)

	ps.compute()

	return nil
}

// Add adds a policy.
// The policy ID (index) is automatically assigned to the first empty slot.
func (ps *Policies) Add(p *Policy) error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	if p == nil {
		return PolicyNilError()
	}
	if ps.count() == MaxPolicies {
		return PoliciesMaxExceededError()
	}
	if existing, ok := ps.policiesMapByName[p.Name]; ok {
		return PolicyAlreadyExistsError(existing.Name, existing.ID)
	}

	// search for the first empty slot
	for id := range ps.policiesArray {
		if ps.policiesArray[id] == nil {
			return ps.set(id, p)
		}
	}

	return nil
}

// Set sets a policy.
// A policy overwrite is allowed only if the policy that is going to be overwritten
// has the same ID and name.
func (ps *Policies) Set(p *Policy) error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	if p == nil {
		return PolicyNilError()
	}

	id := p.ID
	if !isIDInRange(id) {
		return PoliciesOutOfRangeError(id)
	}

	existing, ok := ps.policiesMapByName[p.Name]
	if ok && existing.ID != id { // name already exists with a different ID
		return PolicyAlreadyExistsError(existing.Name, existing.ID)
	}

	return ps.set(id, p)
}

// Remove removes a policy by name.
func (ps *Policies) Remove(name string) error {
	ps.rwmu.Lock()
	defer ps.rwmu.Unlock()

	p, ok := ps.policiesMapByName[name]
	if !ok {
		return PolicyNotFoundByNameError(name)
	}

	id := p.ID
	ps.policiesList = append(ps.policiesList[:id], ps.policiesList[id+1:]...)
	delete(ps.policiesMapByID, id)
	delete(ps.policiesMapByName, p.Name)
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

	if p, ok := ps.policiesMapByName[name]; ok {
		return p, nil
	}

	return nil, PolicyNotFoundByNameError(name)
}

// MatchedNames returns a list of matched policies names based on
// the given matched bitmap.
func (ps *Policies) MatchedNames(matched uint64) []string {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	names := []string{}

	for _, p := range ps.all() {
		if utils.HasBit(matched, uint(p.ID)) {
			names = append(names, p.Name)
		}
	}

	return names
}

// all returns a map of all policies by ID.
func (ps *Policies) all() map[int]*Policy {
	return ps.policiesMapByID
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

	nPols := NewPolicies()

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

	for _, p := range ps.all() {
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

	for _, p := range ps.all() {
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
	for _, p := range ps.policiesMapByID {
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
	return id >= 0 && id < MaxPolicies
}
