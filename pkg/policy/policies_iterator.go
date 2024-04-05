package policy

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
