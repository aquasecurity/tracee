package ebpf

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// policyManager is a thread-safe struct that manages the enabled policies for each rule
type policyManager struct {
	mutex sync.Mutex
	rules map[events.ID]uint64
}

func newPolicyManager() *policyManager {
	return &policyManager{
		mutex: sync.Mutex{},
		rules: make(map[events.ID]uint64),
	}
}

// IsRuleEnabled returns true if a given event policy is enabled for a given rule
func (pm *policyManager) IsRuleEnabled(matchedPolicies uint64, ruleId events.ID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	policyMask, ok := pm.rules[ruleId]
	if !ok {
		return false
	}

	return policyMask&matchedPolicies != 0
}

// EnableRule enables a rule for a given event policy
func (pm *policyManager) EnableRule(policyId int, ruleId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	policyMask := pm.rules[ruleId]
	utils.SetBit(&policyMask, uint(policyId))

	pm.rules[ruleId] = policyMask
}

// DisableRule disables a rule for a given event policy
func (pm *policyManager) DisableRule(policyId int, ruleId events.ID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	policyMask := pm.rules[ruleId]
	utils.ClearBit(&policyMask, uint(policyId))

	pm.rules[ruleId] = policyMask
}
