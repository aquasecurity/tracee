package flags

import (
	"errors"
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
		return fmt.Errorf("invalid scope option specified (%s), run 'man scope' for more info", expr)
	}

	return fmt.Errorf("invalid scope option specified (%s), use 'tracee man scope' for more info", expr)
}

func InvalidFlagEmpty() error {
	return errors.New("empty flag")
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

// Help-related error messages
func InvalidCaptureOptionError() error {
	return errors.New("invalid capture option specified, use 'tracee man capture' for more info")
}

func InvalidOutputFlagError(flag string) error {
	return fmt.Errorf("invalid output flag: %s, use 'tracee man output' for more info", flag)
}

func InvalidOutputOptionError(option string) error {
	return fmt.Errorf("invalid output option: %s, use 'tracee man output' for more info", option)
}

func EmptyOutputFlagError(flagType string) error {
	return fmt.Errorf("%s flag can't be empty, use 'tracee man output' for more info", flagType)
}

func InvalidOutputURIError(flag, uri string) error {
	return fmt.Errorf("invalid uri for %s output %q. Use 'tracee man output' for more info", flag, uri)
}

func DuplicateOutputPathError(path string) error {
	return fmt.Errorf("cannot use the same path for multiple outputs: %s, use 'tracee man output' for more info", path)
}

func NoneOutputPathError() error {
	return errors.New("none output does not support path. Use 'tracee man output' for more info")
}

func InvalidLogOptionError(opt, details string) error {
	return fmt.Errorf("invalid log option: %s, %s, use 'tracee man log' for more info", opt, details)
}

func InvalidLogOptionValueError(opt, details string) error {
	return fmt.Errorf("invalid log option value: %s, %s, use 'tracee man log' for more info", opt, details)
}

func UnrecognizedOutputFormatError(format string) error {
	return fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', or 'gotemplate='. Use 'tracee man output' for more info", format)
}

func UnsupportedContainerRuntimeError() error {
	return errors.New("unsupported container runtime in sockets flag (see 'tracee man containers' for supported runtimes)")
}
