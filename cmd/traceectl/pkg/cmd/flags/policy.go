package flags

import "fmt"

const PolicyFlag = "policy"

func PreparePolicy(policySlice []string) ([]string, error) {
	if len(policySlice) > 0 {
		return policySlice, nil
	}
	return nil, fmt.Errorf("policy cannot be empty")
}
