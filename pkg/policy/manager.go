package policy

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// PolicyManager is a thread-safe struct that manages the enabled policies for each rule
type PolicyManager struct {
	mutex     sync.Mutex
	rules     map[events.ID]*eventState
	snapshots *snapshots
}

// eventState is a struct that holds the state of a given event
type eventState struct {
	policyMask uint64
	enabled    bool
}

func newPolicyManager() *PolicyManager {
	return &PolicyManager{
		mutex:     sync.Mutex{},
		rules:     make(map[events.ID]*eventState),
		snapshots: newSnapshots(),
	}
}

var (
	manager     *PolicyManager // singleton
	managerOnce sync.Once
)

// Manager returns the singleton PolicyManager
func Manager() *PolicyManager {
	managerOnce.Do(func() {
		manager = newPolicyManager()
	})

	return manager
}

func (pm *PolicyManager) GetPolicyBuilder(p Policy) PolicyBuilder {
	if p == nil {
		return nil
	}

	new := p.Clone().(PolicyBuilder)

	return new
}

// Snapshots returns the Policies snapshots
// TODO: remove this publicizer method when entire logic is moved to PolicyManager
func (pm *PolicyManager) Snapshots() *snapshots {
	return pm.snapshots
}

func (pm *PolicyManager) GetCurrent() (Policies, error) {
	ps, err := pm.snapshots.GetLast()
	if err != nil {
		return nil, err
	}

	return ps, nil
}

func (pm *PolicyManager) GetVersion(version uint16) (Policies, error) {
	ps, err := pm.snapshots.Get(version)
	if err != nil {
		return nil, err
	}

	return ps, nil
}

func (pm *PolicyManager) ApplyPolicies(ps *Policies) (*Policies, error) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	return ps, nil
}

// IsEnabled tests if a event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (pm *PolicyManager) IsEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.isEventEnabled(ruleId) {
		return false
	}

	return pm.isRuleEnabled(matchedPolicies, ruleId)
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsRuleEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	return pm.isRuleEnabled(matchedPolicies, ruleId)
}

// not synchronized, use IsRuleEnabled instead
func (pm *PolicyManager) isRuleEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	state, ok := pm.rules[ruleId]
	if !ok {
		return false
	}

	return state.policyMask&matchedPolicies != 0
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsEventEnabled(evenId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	return pm.isEventEnabled(evenId)
}

// not synchronized, use IsEventEnabled instead
func (pm *PolicyManager) isEventEnabled(evenId events.ID) bool {
	state, ok := pm.rules[evenId]
	if !ok {
		return false
	}

	return state.enabled
}

// not synchronized, use EnableRule instead
func (pm *PolicyManager) enableRule(policyId int, ruleId events.ID) {
	state, ok := pm.rules[ruleId]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		state = &eventState{enabled: true}
	}

	utils.SetBit(&state.policyMask, uint(policyId))

	pm.rules[ruleId] = state
}

// EnableRules enables all rules for a given collection of policies
func (pm *PolicyManager) EnableRules(policies Policies) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	for p := range policies.Map() {
		it := p.CreateEventsToTraceIterator()
		for it.HasNext() {
			e := it.GetNext()
			pm.enableRule(p.GetID(), e)
		}
	}
}

// EnableRule enables a rule for a given event policy
func (pm *PolicyManager) EnableRule(policyId int, ruleId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.enableRule(policyId, ruleId)
}

// DisableRule disables a rule for a given event policy
func (pm *PolicyManager) DisableRule(policyId int, ruleId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	state, ok := pm.rules[ruleId]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		state = &eventState{enabled: true}
	}

	utils.ClearBit(&state.policyMask, uint(policyId))

	pm.rules[ruleId] = state
}

// EnableEvent enables a given event
func (pm *PolicyManager) EnableEvent(eventId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	state, ok := pm.rules[eventId]
	if !ok {
		pm.rules[eventId] = &eventState{enabled: true}
		return
	}

	state.enabled = true
}

// DisableEvent disables a given event
func (pm *PolicyManager) DisableEvent(eventId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	state, ok := pm.rules[eventId]
	if !ok {
		pm.rules[eventId] = &eventState{enabled: false}
		return
	}

	state.enabled = false
}
