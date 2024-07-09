package policy

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// PolicyManager is a thread-safe struct that manages the enabled policies for each rule
type PolicyManager struct {
	mu    sync.RWMutex
	ps    *policies
	rules map[events.ID]*eventFlags
}

func NewPolicyManager(policies ...*Policy) *PolicyManager {
	ps := NewPolicies()
	for _, p := range policies {
		if err := ps.set(p); err != nil {
			logger.Errorw("failed to set policy", "error", err)
		}
	}

	return &PolicyManager{
		mu:    sync.RWMutex{},
		ps:    ps,
		rules: make(map[events.ID]*eventFlags),
	}
}

// IsEnabled tests if a event, or a policy per event is enabled (in the future it will also check if a policy is enabled)
// TODO: add metrics about an event being enabled/disabled, or a policy being enabled/disabled?
func (pm *PolicyManager) IsEnabled(matchedPolicies uint64, id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.isEventEnabled(id) {
		return false
	}

	return pm.isRuleEnabled(matchedPolicies, id)
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsRuleEnabled(matchedPolicies uint64, id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isRuleEnabled(matchedPolicies, id)
}

// not synchronized, use IsRuleEnabled instead
func (pm *PolicyManager) isRuleEnabled(matchedPolicies uint64, id events.ID) bool {
	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.policiesEmit&matchedPolicies != 0
}

// IsEventEnabled returns true if a given event policy is enabled for a given rule
func (pm *PolicyManager) IsEventEnabled(id events.ID) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isEventEnabled(id)
}

// not synchronized, use IsEventEnabled instead
func (pm *PolicyManager) isEventEnabled(id events.ID) bool {
	flags, ok := pm.rules[id]
	if !ok {
		return false
	}

	return flags.enabled
}

// EnableRule enables a rule for a given event policy
func (pm *PolicyManager) EnableRule(policyId int, id events.ID) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		flags = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		pm.rules[id] = flags
	}

	flags.enableEmission(policyId)

	return nil
}

// DisableRule disables a rule for a given event policy
func (pm *PolicyManager) DisableRule(policyId int, id events.ID) error {
	if !isIDInRange(policyId) {
		return PoliciesOutOfRangeError(policyId)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		// if you enabling/disabling a rule for an event that
		// was not enabled/disabled yet, we assume the event should be enabled
		flags = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		pm.rules[id] = flags
	}

	flags.disableEmission(policyId)

	return nil
}

// EnableEvent enables a given event
func (pm *PolicyManager) EnableEvent(id events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		pm.rules[id] = newEventFlags(
			eventFlagsWithEnabled(true),
		)
		return
	}

	flags.enableEvent()
}

// DisableEvent disables a given event
func (pm *PolicyManager) DisableEvent(id events.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	flags, ok := pm.rules[id]
	if !ok {
		pm.rules[id] = newEventFlags(
			eventFlagsWithEnabled(false),
		)
		return
	}

	flags.disableEvent()
}

//
// Policies methods made available by PolicyManager.
// Some are transitive (tidying), some are not.
//

func (pm *PolicyManager) CreateUserlandIterator() utils.Iterator[*Policy] {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// The returned iterator is not thread-safe since its underlying data is not a copy.
	// A possible solution would be to use the snapshot mechanism with timestamps instead
	// of version numbers.
	return pm.ps.createUserlandIterator()
}

func (pm *PolicyManager) CreateAllIterator() utils.Iterator[*Policy] {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// The returned iterator is not thread-safe since its underlying data is not a copy.
	// A possible solution would be to use the snapshot mechanism with timestamps instead
	// of version numbers.
	return pm.ps.createAllIterator()
}

func (pm *PolicyManager) FilterableInUserland(bitmap uint64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return (bitmap & pm.ps.filterInUserland()) != 0
}

func (pm *PolicyManager) WithContainerFilterEnabled() uint64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.ps.withContainerFilterEnabled()
}

func (pm *PolicyManager) MatchedNames(matched uint64) []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.ps.matchedNames(matched)
}

func (pm *PolicyManager) LookupByName(name string) (*Policy, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.ps.lookupByName(name)
}

func (pm *PolicyManager) UpdateBPF(
	bpfModule *bpf.Module,
	cts *containers.Containers,
	eventsState map[events.ID]events.EventState,
	eventsParams map[events.ID][]bufferdecoder.ArgType,
	createNewMaps bool,
	updateProcTree bool,
) (*PoliciesConfig, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.ps.updateBPF(bpfModule, cts, eventsState, eventsParams, createNewMaps, updateProcTree)
}
