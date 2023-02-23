package flags

import (
	"fmt"
)

func InvalidSetError(set string) error {
	return fmt.Errorf("invalid set to trace: %s", set)
}

func InvalidEventError(event string) error {
	return fmt.Errorf("invalid event to trace: %s", event)
}

func InvalidEventExcludeError(event string) error {
	return fmt.Errorf("invalid event to exclude: %s", event)
}

func InvalidFilterOptionError(expr string) error {
	return fmt.Errorf("invalid filter option specified (%s), use '--filter help' for more info", expr)
}
