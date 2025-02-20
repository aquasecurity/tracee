package policy

import (
	"errors"
	"fmt"
)

func PolicyNilError() error {
	return errors.New("policy cannot be nil")
}

func PoliciesMaxExceededError() error {
	return fmt.Errorf("policies maximum exceeded [%d]", PolicyMax)
}

func PoliciesOutOfRangeError(idx int) error {
	return fmt.Errorf("policies index [%d] out-of-range [0-%d]", idx, PolicyMax-1)
}

func PolicyAlreadyExistsError(name string, idx int) error {
	return fmt.Errorf("policy [%s] already exists at index [%d]", name, idx)
}

func PolicyNotFoundByIDError(idx int) error {
	return fmt.Errorf("policy not found at index [%d]", idx)
}

func PolicyNotFoundByNameError(name string) error {
	return fmt.Errorf("policy [%s] not found", name)
}
