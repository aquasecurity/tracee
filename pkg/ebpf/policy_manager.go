package ebpf

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// policyManager is a thread-safe struct that manages the enabled policies for each rule
type policyManager struct {
	mutex sync.Mutex
	rules map[events.ID]*eventState
}

// eventState is a struct that holds the state of a given event
type eventState struct {
	policyMask uint64
	enabled    bool
}

func newPolicyManager() *policyManager {
	return &policyManager{
		mutex: sync.Mutex{},
		rules: make(map[events.ID]*eventState),
	}
}

// IsEnabled tests if a event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (pm *policyManager) IsEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.isEventEnabled(ruleId) {
		return false
	}

	return pm.isRuleEnabled(matchedPolicies, ruleId)
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (pm *policyManager) IsRuleEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	return pm.isRuleEnabled(matchedPolicies, ruleId)
}

// not synchronized, use IsRuleEnabled instead
func (pm *policyManager) isRuleEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	state, ok := pm.rules[ruleId]
	if !ok {
		return false
	}

	return state.policyMask&matchedPolicies != 0
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (pm *policyManager) IsEventEnabled(evenId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	return pm.isEventEnabled(evenId)
}

// not synchronized, use IsEventEnabled instead
func (pm *policyManager) isEventEnabled(evenId events.ID) bool {
	state, ok := pm.rules[evenId]
	if !ok {
		return false
	}

	return state.enabled
}

// EnableRule enables a rule for a given event policy
func (pm *policyManager) EnableRule(policyId int, ruleId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	state, ok := pm.rules[ruleId]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		state = &eventState{enabled: true}
	}

	utils.SetBit(&state.policyMask, uint(policyId))

	pm.rules[ruleId] = state
}

// DisableRule disables a rule for a given event policy
func (pm *policyManager) DisableRule(policyId int, ruleId events.ID) {
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
func (pm *policyManager) EnableEvent(eventId events.ID) {
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
func (pm *policyManager) DisableEvent(eventId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	state, ok := pm.rules[eventId]
	if !ok {
		pm.rules[eventId] = &eventState{enabled: false}
		return
	}

	state.enabled = false
}
