package flags

import (
	"fmt"
)

func InvalidEventError(event string) error {
	return fmt.Errorf("invalid event to trace: %s", event)
}

func InvalidEventExcludeError(event string) error {
	return fmt.Errorf("invalid event to exclude: %s", event)
}

func InvalidScopeOptionError(expr string, newBinary bool) error {
	if newBinary {
		// TODO: build man page
		// return fmt.Errorf("invalid scope option specified (%s), see 'tracee-scope' man page for more info", expr)
		return fmt.Errorf("invalid scope option specified (%s), use '--help' for more info", expr)
	}

	return fmt.Errorf("invalid scope option specified (%s), use '--scope help' for more info", expr)
}

func InvalidFlagEmpty() error {
	return fmt.Errorf("empty flag")
}

func InvalidFilterFlagFormat(expression string) error {
	return fmt.Errorf("invalid flag format: %s", expression)
}

func InvalidFlagOperator(expression string) error {
	return fmt.Errorf("invalid flag operator: %s", expression)
}

func InvalidFlagValue(expression string) error {
	return fmt.Errorf("invalid flag value: %s", expression)
}
