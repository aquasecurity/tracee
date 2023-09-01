package ebpf

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func TestEventsManagerEnableRule(t *testing.T) {
	policyManager := newPolicyManager()

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	assert.False(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableRule(1, events.SecurityBPF)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableRule(2, events.SecurityBPF)
	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))
}

func TestEventsManagerDisableRule(t *testing.T) {
	policyManager := newPolicyManager()

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	policyManager.EnableRule(1, events.SecurityBPF)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.DisableRule(1, events.SecurityBPF)

	assert.False(t, policyManager.IsRuleEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy1And2Mached, events.SecurityBPF))
}

func TestEventsManagerEnableAndDisableConcurrent(t *testing.T) {
	eventsToEnable := []events.ID{
		events.SecurityBPF,
		events.SchedGetPriorityMax,
		events.SchedProcessExec,
		events.SchedProcessExit,
		events.Ptrace,
	}

	eventsToDisable := []events.ID{
		events.SecurityBPFMap,
		events.Openat2,
		events.SchedProcessFork,
		events.MagicWrite,
		events.FileModification,
	}

	policyManager := newPolicyManager()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		for i := 0; i < policy.MaxPolicies; i++ {
			for _, e := range eventsToEnable {
				policyManager.EnableRule(i, e)
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for i := 0; i < policy.MaxPolicies; i++ {
			for _, e := range eventsToDisable {
				policyManager.DisableRule(i, e)
			}
		}
		wg.Done()
	}()

	wg.Wait()

	for i := 0; i < policy.MaxPolicies; i++ {
		for _, e := range eventsToEnable {
			assert.True(t, policyManager.IsRuleEnabled(policy.AllPoliciesOn, e))
		}
		for _, e := range eventsToDisable {
			assert.False(t, policyManager.IsRuleEnabled(policy.AllPoliciesOn, e))
		}
	}
}
