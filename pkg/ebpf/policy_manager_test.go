package ebpf

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func TestPolicyManagerEnableRule(t *testing.T) {
	t.Parallel()

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

func TestPolicyManagerDisableRule(t *testing.T) {
	t.Parallel()

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

func TestPolicyManagerEnableAndDisableRuleConcurrent(t *testing.T) {
	t.Parallel()

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

func TestPolicyManagerEnableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	assert.False(t, policyManager.isEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.isEventEnabled(events.SecurityFileOpen))
	assert.False(t, policyManager.isEventEnabled(events.SecuritySocketAccept))

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.isEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.isEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.isEventEnabled(events.SecuritySocketAccept))
}

func TestPolicyManagerDisableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	policyManager.EnableEvent(events.SecurityBPF)
	policyManager.EnableEvent(events.SecurityFileOpen)
	policyManager.EnableEvent(events.SecuritySocketAccept)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))

	policyManager.DisableEvent(events.SecurityBPF)
	policyManager.DisableEvent(events.SecurityFileOpen)

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))
	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
	assert.True(t, policyManager.IsEventEnabled(events.SecuritySocketAccept))
}

func TestPolicyManagerEnableAndDisableEventConcurrent(t *testing.T) {
	t.Parallel()

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

	assert.False(t, policyManager.IsEventEnabled(events.SecurityBPF))

	policyManager.EnableRule(1, events.SecurityBPF)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityBPF))
}

func TestDisableRuleAlsoEnableEvent(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	assert.False(t, policyManager.IsEventEnabled(events.SecurityFileOpen))

	policyManager.DisableRule(1, events.SecurityFileOpen)

	assert.True(t, policyManager.IsEventEnabled(events.SecurityFileOpen))
}

func TestPolicyManagerIsEnabled(t *testing.T) {
	t.Parallel()

	policyManager := newPolicyManager()

	policy1Mached := uint64(0b10)
	policy2Mached := uint64(0b100)
	policy1And2Mached := uint64(0b110)

	assert.False(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableRule(1, events.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableRule(2, events.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.DisableEvent(events.SecurityBPF)

	assert.False(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.False(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))

	policyManager.EnableEvent(events.SecurityBPF)

	assert.True(t, policyManager.IsEnabled(policy1Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy2Mached, events.SecurityBPF))
	assert.True(t, policyManager.IsEnabled(policy1And2Mached, events.SecurityBPF))
}
