package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
)

func deriveError(id events.ID, err error) error {
	return fmt.Errorf("failed to derive event %d: %v", id, err)
}

func unexpectedArgCountError(name string, expected int, actual int) error {
	return fmt.Errorf("error deriving event \"%s\": expected %d arguments but given %d", name, expected, actual)
}
