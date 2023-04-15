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

func InvalidFilterOptionError(expr string, newBinary bool) error {
	if newBinary {
		return fmt.Errorf("invalid filter option specified (%s), use '--help filter' for more info", expr)
	}

	return fmt.Errorf("invalid filter option specified (%s), use '--filter help' for more info", expr)
}

func InvalidFlagEmpty() error {
	return fmt.Errorf("empty flag")
}

func InvalidFlagOperator(expression string) error {
	return fmt.Errorf("invalid flag operator: %s", expression)
}

func InvalidFlagValue(expression string) error {
	return fmt.Errorf("invalid flag value: %s", expression)
}
