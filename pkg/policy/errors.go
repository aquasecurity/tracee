package policy

import (
	"fmt"
)

type policyError struct {
	msg string
}

func (e *policyError) Error() string {
	return e.msg
}

func (e *policyError) Is(target error) bool {
	t, ok := target.(*policyError)
	if !ok {
		return false
	}
	return e.msg == t.msg
}

func PolicyNilError() error {
	return &policyError{msg: "policy cannot be nil"}
}

func PolicyAlreadyExistsError(name string) error {
	return &policyError{msg: fmt.Sprintf("policy [%s] already exists", name)}
}

func PolicyNotFoundByNameError(name string) error {
	return &policyError{msg: fmt.Sprintf("policy [%s] not found", name)}
}

func SelectEventError(eventName string) error {
	return &policyError{msg: fmt.Sprintf("failed to select event %s", eventName)}
}
