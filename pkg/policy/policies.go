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
	PolicyMax  = int(64)
	PolicyAll  = ^uint64(0)
	PolicyNone = uint64(0)
)

var AlwaysSubmit = events.EventState{
	Submit: PolicyAll,
}

type Policies struct {
	rwmu sync.RWMutex

	version           uint16                    // updated on snapshot store
	bpfInnerMaps      map[string]*bpf.BPFMapLow // BPF inner maps
	policiesArray     [PolicyMax]*Policy        // underlying policies array for fast access of empty slots
	policiesMapByID   map[int]*Policy           // all policies map by ID
	policiesMapByName map[string]*Policy        // all policies map by name
	policiesList      []*Policy                 // all policies list

	// computed values

	// policies
	userlandPolicies        []*Policy // reduced list with userland filterable policies (read in a hot path)
	uidFilterMin            uint64
	uidFilterMax            uint64
	pidFilterMin            uint64
	pidFilterMax            uint64
	uidFilterableInUserland bool
	pidFilterableInUserland bool
	filterableInUserland    uint64 // bitmap of policies that must be filtered in userland
	containerFiltersEnabled uint64 // bitmap of policies that have at least one container filter type enabled
	// rules
	lastRulesVersions map[events.ID]uint8
	policyRulesMap    map[ruleKey]map[int]*Policy
}

func NewPolicies() *Policies {
	return &Policies{
		rwmu:                    sync.RWMutex{},
		version:                 0,
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
		lastRulesVersions:       map[events.ID]uint8{},
		policyRulesMap:          map[ruleKey]map[int]*Policy{},
	}
}

// Compile-time check to ensure that Policies implements the Cloner interface
var _ utils.Cloner[*Policies] = &Policies{}

func (ps *Policies) count() int {
	return len(ps.policiesMapByID)
}

func (ps *Policies) Count() int {
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()

	return ps.count()
}

func (ps *Policies) Version() uint16 {
	return ps.version
}

// WithContainerFilterEnabled returns a bitmap of policies that have at least one container filter type enabled.
func (ps *Policies) WithContainerFilterEnabled() uint64 {
	return ps.containerFiltersEnabled
}

// ContainerFilterEnabled returns true if at least one policy has a container filter type enabled.
func (ps *Policies) ContainerFilterEnabled() bool {
	return ps.WithContainerFilterEnabled() > 0
}

// FilterableInUserland returns a bitmap of policies that must be filtered in userland
// (ArgFilter, RetFilter, ScopeFilter, UIDFilter and PIDFilter).
func (ps *Policies) FilterableInUserland() uint64 {
	return atomic.LoadUint64(&ps.filterableInUserland)
}

// set sets a policy at the given ID (index).
func (ps *Policies) set(id int, p *Policy) error {
	p.ID = id
	ps.policiesArray[id] = p
	ps.policiesMapByID[id] = p
	ps.policiesMapByName[p.Name] = p
	ps.policiesList = append(ps.policiesList, p)

	ps.compute()

	for eID := range p.EventsToTrace {
		newRuleID := ps.lastRulesVersions[eID] + 1
		// check against the maximum 64
		// set new rules version
		p.ruleVersionByEvent[eID] = newRuleID
		ps.lastRulesVersions[eID] = newRuleID

		// update policyRulesMap
		rkey := ruleKey{
			eventID: eID,
			ruleID:  newRuleID,
		}
		if _, ok := ps.policyRulesMap[rkey]; !ok {
			ps.policyRulesMap[rkey] = make(map[int]*Policy)
		}
		ps.policyRulesMap[rkey][id] = p
	}

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
	if ps.count() == PolicyMax {
		return PoliciesMaxExceededError()
	}
	if existing, ok := ps.policiesMapByName[p.Name]; ok {
		return PolicyAlreadyExistsError(existing.Name, existing.ID)
	}

	// search for the first empty slot
	for id, slot := range ps.allFromArray() {
		if slot == nil {
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

	for _, p := range ps.allFromMap() {
		if utils.HasBit(matched, uint(p.ID)) {
			names = append(names, p.Name)
		}
	}

	return names
}

// Clone returns a deep copy of Policies.
func (ps *Policies) Clone() *Policies {
	if ps == nil {
		return nil
	}

	nPols := NewPolicies()

	// Deep copy of all policies
	ps.rwmu.RLock()
	defer ps.rwmu.RUnlock()
	for _, p := range ps.allFromArray() {
		if p == nil {
			continue
		}
		if err := nPols.Set(p.Clone()); err != nil {
			logger.Errorw("Cloning policy %s: %v", p.Name, err)
			return nil
		}
	}

	return nPols
}

// allFromMap returns a map of allFromMap policies by ID.
// When iterating, the order is not guaranteed.
func (ps *Policies) allFromMap() map[int]*Policy {
	return ps.policiesMapByID
}

// allFromArray returns an slice of the underlying policies array.
// When iterating, the order is guaranteed.
func (ps *Policies) allFromArray() []*Policy {
	return ps.policiesArray[:]
}

func isIDInRange(id int) bool {
	return id >= 0 && id < PolicyMax
}
