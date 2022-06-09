package capabilities

import (
	"fmt"
	"strings"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type MissingCapabilitiesError struct {
	MissingCaps []cap.Value
}

type DropCapabilitiesError struct {
	Err error
}

func (missCapErr *MissingCapabilitiesError) Error() string {
	var missingCapsNames []string
	for _, missingCap := range missCapErr.MissingCaps {
		missingCapsNames = append(missingCapsNames, strings.ToUpper(missingCap.String()))
	}
	return fmt.Sprintf("insufficient capabilities to run: missing %s", missingCapsNames)
}

func (missCapErr *MissingCapabilitiesError) Is(target error) bool {
	_, ok := target.(*MissingCapabilitiesError)
	return ok
}

func (dropCapErr *DropCapabilitiesError) Error() string {
	return fmt.Sprintf("couldn't drop capabilities: %s", dropCapErr.Err)
}

func (dropCapErr *DropCapabilitiesError) Unwrap() error {
	return dropCapErr.Err
}

func (dropCapErr *DropCapabilitiesError) Is(target error) bool {
	_, ok := target.(*DropCapabilitiesError)
	return ok
}
