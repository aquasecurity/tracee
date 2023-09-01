package ebpf

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/policy"
)

func TestPoliciesManagerEnablePolicy(t *testing.T) {
	policiesManager := &policiesManager{policyMask: 0}

	for i := 0; i < policy.MaxPolicies; i++ {
		policiesManager.EnablePolicy(i)
	}

	assert.Equal(t, uint64(policy.AllPoliciesOn), policiesManager.policyMask)
}

func TestPoliciesManagerDisablePolicy(t *testing.T) {
	policiesManager := &policiesManager{policyMask: policy.AllPoliciesOn}

	for i := 0; i < policy.MaxPolicies; i++ {
		policiesManager.DisablePolicy(i)
	}

	assert.Equal(t, uint64(0), policiesManager.policyMask)
}

func TestPoliciesManagerEnableAndDisableConcurrency(t *testing.T) {
	policiesManager := &policiesManager{policyMask: 0b10101010}

	wg := &sync.WaitGroup{}

	// revert the current state of the policy mask

	wg.Add(1)
	go func() {
		// enable even policies
		for i := 0; i < 8; i++ {
			if i%2 == 0 {
				policiesManager.EnablePolicy(i)
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		// disable odd policies
		for i := 0; i < 8; i++ {
			if i%2 != 0 {
				policiesManager.DisablePolicy(i)
			}
		}
		wg.Done()
	}()

	wg.Wait()

	assert.Equal(t, uint64(0b01010101), policiesManager.policyMask)
}

func TestPoliciesManagerMatch(t *testing.T) {
	var matchedPolicy0 uint64 = 0b00000001
	var matchedPolicy0and3 uint64 = 0b00001001

	policiesManager := &policiesManager{policyMask: policy.AllPoliciesOn}

	policiesManager.DisablePolicy(0)

	assert.Equal(t, uint64(0), policiesManager.Match(matchedPolicy0))
	assert.Equal(t, uint64(0b00001000), policiesManager.Match(matchedPolicy0and3))

	policiesManager.EnablePolicy(0)

	assert.Equal(t, uint64(0b00000001), policiesManager.Match(matchedPolicy0))
	assert.Equal(t, uint64(0b00001001), policiesManager.Match(matchedPolicy0and3))
}
