package policy

import "github.com/aquasecurity/tracee/pkg/utils"

// PoliciesIterator is an iterator for Policies.
type PoliciesIterator struct {
	policies []*Policy
	index    int
}

// HasNext returns true if there are more policies to iterate.
func (i *PoliciesIterator) HasNext() bool {
	return i.index < len(i.policies)
}

// Next returns the next policy in the iteration.
func (i *PoliciesIterator) Next() *Policy {
	if !i.HasNext() {
		return nil
	}

	p := i.policies[i.index]
	i.index++

	return p
}

// CreateUserlandIterator returns a new iterator for a reduced list of policies
// which must be filtered in userland (ArgFilter, RetFilter, ScopeFilter,
// UIDFilter and PIDFilter).
func (ps *Policies) CreateUserlandIterator() utils.Iterator[*Policy] {
	return &PoliciesIterator{
		policies: ps.userlandPolicies,
		index:    0,
	}
}

// CreateAllIterator returns a new iterator for all policies.
func (ps *Policies) CreateAllIterator() utils.Iterator[*Policy] {
	return &PoliciesIterator{
		policies: ps.policiesList,
		index:    0,
	}
}
