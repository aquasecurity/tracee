package policy

import "github.com/aquasecurity/tracee/common/interfaces"

// policiesIterator is an iterator for Policies.
type policiesIterator struct {
	policies []*Policy
	index    int
}

// HasNext returns true if there are more policies to iterate.
func (i *policiesIterator) HasNext() bool {
	return i.index < len(i.policies)
}

// Next returns the next policy in the iteration.
func (i *policiesIterator) Next() *Policy {
	if !i.HasNext() {
		return nil
	}

	p := i.policies[i.index]
	i.index++

	return p
}

// createUserlandIterator returns a new iterator for a reduced list of policies
// which must be filtered in userland (ArgFilter, RetFilter, ScopeFilter,
// UIDFilter and PIDFilter).
func (ps *policies) createUserlandIterator() interfaces.Iterator[*Policy] {
	return &policiesIterator{
		policies: ps.userlandPolicies,
		index:    0,
	}
}

// createAllIterator returns a new iterator for all policies.
func (ps *policies) createAllIterator() interfaces.Iterator[*Policy] {
	return &policiesIterator{
		policies: ps.policiesList,
		index:    0,
	}
}
