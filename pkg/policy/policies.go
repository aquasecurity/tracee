package policy

import (
	"sync/atomic"

	bpf "github.com/aquasecurity/libbpfgo"

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

var AlwaysSubmit = events.EventState{
	Submit: PolicyAll,
}

type policies struct {
	bpfInnerMaps      map[string]*bpf.BPFMapLow // BPF inner maps
	policiesArray     [PolicyMax]*Policy        // underlying policies array for fast access of empty slots
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

func NewPolicies() *policies {
	return &policies{
		bpfInnerMaps:            map[string]*bpf.BPFMapLow{},
		policiesArray:           [PolicyMax]*Policy{},
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

// Compile-time check to ensure that Policies implements the Cloner interface
var _ utils.Cloner[*policies] = &policies{}

func (ps *policies) count() int {
	return len(ps.policiesMapByID)
}

// Deprecated: version returns the version of the Policies.
// Will be removed soon.
func (ps *policies) version() uint16 {
	return 1 // version will be removed soon
}

// withContainerFilterEnabled returns a bitmap of policies that have at least one container filter type enabled.
func (ps *policies) withContainerFilterEnabled() uint64 {
	return ps.containerFiltersEnabled
}

// containerFilterEnabled returns true if at least one policy has a container filter type enabled.
func (ps *policies) containerFilterEnabled() bool {
	return ps.withContainerFilterEnabled() > 0
}

// filterInUserland returns a bitmap of policies that must be filtered in userland
// (ArgFilter, RetFilter, ScopeFilter, UIDFilter and PIDFilter).
func (ps *policies) filterInUserland() uint64 {
	return atomic.LoadUint64(&ps.filterableInUserland)
}

// set sets a policy in the policies, given an ID.
func set(ps *policies, id int, p *Policy) error {
	p.ID = id
	ps.policiesArray[id] = p
	ps.policiesMapByID[id] = p
	ps.policiesMapByName[p.Name] = p
	ps.policiesList = append(ps.policiesList, p)

	ps.compute()

	return nil
}

// add adds a policy.
// The policy ID (index) is automatically assigned to the first empty slot.
func (ps *policies) add(p *Policy) error {
	if p == nil {
		return PolicyNilError()
	}
	if ps.count() == PolicyMax {
		return PoliciesMaxExceededError()
	}
	if existing, ok := ps.policiesMapByName[p.Name]; ok {
		return PolicyAlreadyExistsError(existing.Name, existing.ID)
	}

	// search for the first empty slot
	for id, slot := range ps.allFromArray() {
		if slot == nil {
			return set(ps, id, p)
		}
	}

	return nil
}

// set sets a policy.
// A policy overwrite is allowed only if the policy that is going to be overwritten
// has the same ID and name.
func (ps *policies) set(p *Policy) error {
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

	return set(ps, id, p)
}

// remove removes a policy by name.
func (ps *policies) remove(name string) error {
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

// lookupById returns a policy by ID.
func (ps *policies) lookupById(id int) (*Policy, error) {
	if !isIDInRange(id) {
		return nil, PoliciesOutOfRangeError(id)
	}

	p := ps.policiesArray[id]
	if p == nil {
		return nil, PolicyNotFoundByIDError(id)
	}
	return p, nil
}

// lookupByName returns a policy by name.
func (ps *policies) lookupByName(name string) (*Policy, error) {
	if p, ok := ps.policiesMapByName[name]; ok {
		return p, nil
	}

	return nil, PolicyNotFoundByNameError(name)
}

// matchedNames returns a list of matched policies names based on
// the given matched bitmap.
func (ps *policies) matchedNames(matched uint64) []string {
	names := []string{}

	for _, p := range ps.allFromMap() {
		if utils.HasBit(matched, uint(p.ID)) {
			names = append(names, p.Name)
		}
	}

	return names
}

// allFromMap returns a map of allFromMap policies by ID.
// When iterating, the order is not guaranteed.
func (ps *policies) allFromMap() map[int]*Policy {
	return ps.policiesMapByID
}

// allFromArray returns an slice of the underlying policies array.
// When iterating, the order is guaranteed.
func (ps *policies) allFromArray() []*Policy {
	return ps.policiesArray[:]
}

func isIDInRange(id int) bool {
	return id >= 0 && id < PolicyMax
}

// Clone returns a deep copy of Policies.
func (ps *policies) Clone() *policies {
	if ps == nil {
		return nil
	}

	nPols := NewPolicies()

	// Deep copy of all policies
	for _, p := range ps.allFromArray() {
		if p == nil {
			continue
		}
		if err := nPols.set(p.Clone()); err != nil {
			logger.Errorw("Cloning policy %s: %v", p.Name, err)
			return nil
		}
	}

	return nPols
}
