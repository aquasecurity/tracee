package ebpf

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func TestPolicyManagerEnableRule(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	assert.False(t, policyManager.IsRuleEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.EnableRule(1, extensions.SecurityBPF)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.EnableRule(2, extensions.SecurityBPF)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy2Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, extensions.SecurityBPF))
}

func TestPolicyManagerDisableRule(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	policyManager.EnableRule(1, extensions.SecurityBPF)

	assert.True(t, policyManager.IsRuleEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsRuleEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.DisableRule(1, extensions.SecurityBPF)

	assert.False(t, policyManager.IsRuleEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy2Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsRuleEnabled(policy1And2Mached, extensions.SecurityBPF))
}

func TestPolicyManagerEnableAndDisableRuleConcurrent(t *testing.T) {
	t.Parallel()

	eventsToEnable := []int{
		extensions.SecurityBPF,
		extensions.SchedGetPriorityMax,
		extensions.SchedProcessExec,
		extensions.SchedProcessExit,
		extensions.Ptrace,
	}

	eventsToDisable := []int{
		extensions.SecurityBPFMap,
		extensions.Openat2,
		extensions.SchedProcessFork,
		extensions.MagicWrite,
		extensions.FileModification,
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

func TestPolicyManagerEnableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	assert.False(t, policyManager.isEventEnabled(extensions.SecurityBPF))
	assert.False(t, policyManager.isEventEnabled(extensions.SecurityFileOpen))
	assert.False(t, policyManager.isEventEnabled(extensions.SecuritySocketAccept))

	policyManager.EnableEvent(extensions.SecurityBPF)
	policyManager.EnableEvent(extensions.SecurityFileOpen)
	policyManager.EnableEvent(extensions.SecuritySocketAccept)

	assert.True(t, policyManager.isEventEnabled(extensions.SecurityBPF))
	assert.True(t, policyManager.isEventEnabled(extensions.SecurityFileOpen))
	assert.True(t, policyManager.isEventEnabled(extensions.SecuritySocketAccept))
}

func TestPolicyManagerDisableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	policyManager.EnableEvent(extensions.SecurityBPF)
	policyManager.EnableEvent(extensions.SecurityFileOpen)
	policyManager.EnableEvent(extensions.SecuritySocketAccept)

	assert.True(t, policyManager.IsEventEnabled(extensions.SecurityBPF))
	assert.True(t, policyManager.IsEventEnabled(extensions.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(extensions.SecuritySocketAccept))

	policyManager.DisableEvent(extensions.SecurityBPF)
	policyManager.DisableEvent(extensions.SecurityFileOpen)

	assert.False(t, policyManager.IsEventEnabled(extensions.SecurityBPF))
	assert.False(t, policyManager.IsEventEnabled(extensions.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(extensions.SecuritySocketAccept))
}

func TestPolicyManagerEnableAndDisableEventConcurrent(t *testing.T) {
	t.Parallel()

	eventsToEnable := []int{
		extensions.SecurityBPF,
		extensions.SchedGetPriorityMax,
		extensions.SchedProcessExec,
		extensions.SchedProcessExit,
		extensions.Ptrace,
	}

	eventsToDisable := []int{
		extensions.SecurityBPFMap,
		extensions.Openat2,
		extensions.SchedProcessFork,
		extensions.MagicWrite,
		extensions.FileModification,
	}

	policyManager := newPolicyManager()

	// activate events
	for _, e := range eventsToDisable {
		policyManager.EnableEvent(e)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		for i := 0; i < policy.MaxPolicies; i++ {
			for _, e := range eventsToEnable {
				policyManager.EnableEvent(e)
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for i := 0; i < policy.MaxPolicies; i++ {
			for _, e := range eventsToDisable {
				policyManager.DisableEvent(e)
			}
		}
		wg.Done()
	}()

	wg.Wait()

	for i := 0; i < policy.MaxPolicies; i++ {
		for _, e := range eventsToEnable {
			assert.True(t, policyManager.IsEventEnabled(e))
		}
		for _, e := range eventsToDisable {
			assert.False(t, policyManager.IsEventEnabled(e))
		}
	}
}

func TestEnableRuleAlsoEnableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	assert.False(t, policyManager.IsEventEnabled(extensions.SecurityBPF))

	policyManager.EnableRule(1, extensions.SecurityBPF)

	assert.True(t, policyManager.IsEventEnabled(extensions.SecurityBPF))
}

func TestDisableRuleAlsoEnableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	assert.False(t, policyManager.IsEventEnabled(extensions.SecurityFileOpen))

	policyManager.DisableRule(1, extensions.SecurityFileOpen)

	assert.True(t, policyManager.IsEventEnabled(extensions.SecurityFileOpen))
}

func TestPolicyManagerIsEnabled(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	assert.False(t, policyManager.IsEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.EnableRule(1, extensions.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.EnableRule(2, extensions.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy2Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.DisableEvent(extensions.SecurityBPF)

	assert.False(t, policyManager.IsEnabled(policy1Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, extensions.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy1And2Mached, extensions.SecurityBPF))

	policyManager.EnableEvent(extensions.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy2Mached, extensions.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, extensions.SecurityBPF))
}
