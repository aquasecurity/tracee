package policy

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
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
	submitAllPolicies = newEventFlags(
		eventFlagsWithSubmit(PolicyAll),
	)
)

type PoliciesBuilder interface {
	utils.Cloner

	Version() uint16
	EventsFlags() events.EventsFlags
	ContainerFilterEnabled() bool // TODO: check if it is needed
	Add(pb PolicyBuilder) error
	Set(id int, pb PolicyBuilder) error
	Delete(id int) error // TODO: change to Remove(name string) error
	Map() map[*policy]int
}

type Policies interface {
	utils.Cloner

	EventsFlags() events.EventsFlags
	Count() int
	Version() uint16
	WithContainerFilterEnabled() uint64
	WithUserlandFilterEnabled() uint64
	LookupById(id int) (Policy, error)
	LookupByName(name string) (Policy, error)
	MatchedNames(matched uint64) []string
	FilterableInUserlandMap() map[*policy]int
	Map() map[*policy]int
}

// TODO: refactor filterEnabledPoliciesMap and filterUserlandPoliciesMap
// maps to use int (Policy id) as key instead of *Policy.
// TODO: create a new map with policy name as key to speed up LookupByName()
type policies struct {
	// rwmu sync.RWMutex

	config                   config.PoliciesConfig
	version                  uint16                    // updated on snapshot store
	versionBPFMaps           map[string]*bpf.BPFMapLow // string: inner map name, *bpf.BPFMapLow: map
	policiesArray            [PolicyMax]*policy        // underlying filter policies array
	filterEnabledPoliciesMap map[*policy]int           // stores enabled policies

	// computed values
	evtsFlags                 *eventsFlags
	filterUserlandPoliciesMap map[*policy]int // stores a reduced map with only userland filterable policies
	uidFilterMin              uint64
	uidFilterMax              uint64
	pidFilterMin              uint64
	pidFilterMax              uint64
	uidFilterableInUserland   bool
	pidFilterableInUserland   bool
	filterableInUserland      uint64 // bitmap of policies that must be filtered in userland
	containerFiltersEnabled   uint64 // bitmap of policies that have at least one container filter type enabled
}

func NewPoliciesBuilder(cfg config.PoliciesConfig) PoliciesBuilder {
	return &policies{
		// rwmu:                      sync.RWMutex{},
		config:                    cfg,
		version:                   0,
		versionBPFMaps:            map[string]*bpf.BPFMapLow{},
		policiesArray:             [PolicyMax]*policy{},
		filterEnabledPoliciesMap:  map[*policy]int{},
		evtsFlags:                 newEventsFlags(),
		filterUserlandPoliciesMap: map[*policy]int{},
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

// eventsFlags returns the events flags of policies.
func (ps *policies) eventsFlags() *eventsFlags {
	return ps.evtsFlags
}

// EventsFlags returns the events flags of policies.
func (ps *policies) EventsFlags() events.EventsFlags {
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	return ps.eventsFlags()
}

// Count returns the number of enabled policies.
func (ps *policies) Count() int {
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	return len(ps.filterEnabledPoliciesMap)
}

func (ps *policies) Version() uint16 {
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	return ps.version
}

// WithContainerFilterEnabled returns a bitmap of policies representing the
// container filter types enabled.
func (ps *policies) WithContainerFilterEnabled() uint64 {
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	return ps.containerFiltersEnabled
}

// ContainerFilterEnabled returns true if at least one policy has a
// container filter type enabled.
func (ps *policies) ContainerFilterEnabled() bool {
	return ps.WithContainerFilterEnabled() > 0
}

// WithUserlandFilterEnabled returns a bitmap of policies that must be filtered in userland
// (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
func (ps *policies) WithUserlandFilterEnabled() uint64 {
	return ps.filterableInUserland
}

// LookupById returns a policy by ID.
func (ps *policies) LookupById(id int) (Policy, error) {
	if !isIDInRange(id) {
		return nil, PoliciesOutOfRangeError(id)
	}

	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	p := ps.policiesArray[id]
	if p == nil {
		return nil, PolicyNotFoundByIDError(id)
	}
	return p, nil
}

// LookupByName returns a policy by name.
func (ps *policies) LookupByName(name string) (Policy, error) {
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	for p := range ps.filterEnabledPoliciesMap {
		if p.GetName() == name {
			return p, nil
		}
	}
	return nil, PolicyNotFoundByNameError(name)
}

// MatchedNames returns a list of matched policies names based on
// the given matched bitmap.
func (ps *policies) MatchedNames(matched uint64) []string {
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()

	names := []string{}

	for p := range ps.filterEnabledPoliciesMap {
		if utils.HasBit(matched, uint(p.GetID())) {
			names = append(names, p.GetName())
		}
	}

	return names
}

// Map returns map with all policies.
//
// It does not return a copy of the map, so it must be used only for iteration and
// after its snapshot has been stored, otherwise it may be in the initial state and
// not contain all policies computed.
func (ps *policies) Map() map[*policy]int {
	return ps.filterEnabledPoliciesMap
}

// FilterableInUserlandMap returns a reduced policies map which must be filtered in
// userland (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
//
// It does not return a copy of the map, so it must be used only for iteration and
// after its snapshot has been stored, otherwise it may be in the initial state and
// not contain all policies computed.
func (ps *policies) FilterableInUserlandMap() map[*policy]int {
	return ps.filterUserlandPoliciesMap
}

// TODO: Runtime API should encapsulate the following calls:
//
// 1. pols := policies.Clone() to get a clone before to apply changes
// 2. policy.Manager().Snapshots().Store(pols) to get the new version snapshot stored
// 3. tracee.populateFilterMaps(pols, true) to update the maps
// 4. and possibly other steps in which we iterate over the policies map

// Clone returns a deep copy of policies.
func (ps *policies) Clone() utils.Cloner {
	if ps == nil {
		return nil
	}

	nPols := NewPoliciesBuilder(ps.config)

	// Deep copy of all policies
	// ps.rwmu.RLock()
	// defer ps.rwmu.RUnlock()
	for _, p := range ps.policiesArray {
		if p == nil {
			continue
		}
		if err := nPols.Add(p.Clone().(PolicyBuilder)); err != nil {
			logger.Errorw("Cloning policy %s: %v", p.GetName(), err)
			return nil
		}
	}

	return nPols
}

//
// Methods which modify the policies
//

// Add adds a policy to policies.
// Its ID (index) is set to the first room found.
// Returns nil if policy is already inserted.
func (ps *policies) Add(p PolicyBuilder) error {
	// ps.rwmu.Lock()
	// defer ps.rwmu.Unlock()

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

func (ps *policies) Set(id int, p PolicyBuilder) error {
	// ps.rwmu.Lock()
	// defer ps.rwmu.Unlock()

	return ps.set(id, p)
}

// Delete deletes a policy from policies.
func (ps *policies) Delete(id int) error {
	// ps.rwmu.Lock()
	// defer ps.rwmu.Unlock()

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

// set, if not err, always reassign values
func (ps *policies) set(id int, p PolicyBuilder) error {
	if p == nil {
		return PolicyNilError()
	}
	if !isIDInRange(id) {
		return PoliciesOutOfRangeError(id)
	}

	pol := p.(*policy)
	// if _, found := ps.filterEnabledPoliciesMap[pol]; found {
	// 	if pol.GetID() != id {
	// 		return PolicyAlreadyExists(pol, id)
	// 	}
	// }

	pol.id = id
	ps.policiesArray[id] = pol
	ps.filterEnabledPoliciesMap[pol] = id

	ps.compute()

	return nil
}

// isIDInRange returns true if the given ID is in the range of policies.
func isIDInRange(id int) bool {
	return id >= 0 && id < PolicyMax
}
