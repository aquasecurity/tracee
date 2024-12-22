package policy

import (
	"fmt"
)

func PolicyNilError() error {
	return fmt.Errorf("policy cannot be nil")
}

func PolicyAlreadyExistsError(name string) error {
	return fmt.Errorf("policy [%s] already exists", name)
}

func PolicyNotFoundByNameError(name string) error {
	return fmt.Errorf("policy [%s] not found", name)
}
