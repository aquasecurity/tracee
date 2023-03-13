package policy

import "fmt"

func PolicyNilError() error {
	return fmt.Errorf("policy cannot be nil")
}

func PolicyNotFoundError(idx int) error {
	return fmt.Errorf("policy not found at index [%d]", idx)
}

func PoliciesMaxExceededError() error {
	return fmt.Errorf("policies maximum exceeded [%d]", MaxPolicies)
}

func PoliciesOutOfRangeError(idx int) error {
	return fmt.Errorf("policies index [%d] out-of-range [0-%d]", idx, MaxPolicies-1)
}

func PolicyAlreadyExists(policy *Policy, id int) error {
	return fmt.Errorf("policy [%+v] already set with different id [%d]", policy, id)
}
