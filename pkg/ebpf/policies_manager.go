package ebpf

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/utils"
)

// policiesManager is a thread-safe mask of enabled policies
type policiesManager struct {
	mutex      sync.Mutex
	policyMask uint64
}

func newPoliciesManager() *policiesManager {
	return &policiesManager{
		mutex:      sync.Mutex{},
		policyMask: 0,
	}
}

// Match returns the matched policies
func (p *policiesManager) Match(matchedPolicies uint64) uint64 {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.policyMask & matchedPolicies
}

// EnablePolicy enables the given policy
func (p *policiesManager) EnablePolicy(id int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	utils.SetBit(&p.policyMask, uint(id))
}

// DisablePolicy disables the given policy
func (p *policiesManager) DisablePolicy(id int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	utils.ClearBit(&p.policyMask, uint(id))
}
