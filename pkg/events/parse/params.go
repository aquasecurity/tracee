package parse

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

func ArgVal[T any](event *trace.Event, argName string) (T, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(T)
			if !ok {
				zeroVal := *new(T)
				return zeroVal, errfmt.Errorf("argument %s is not of type %T", argName, zeroVal)
			}
			return val, nil
		}
	}
	return *new(T), errfmt.Errorf("argument %s not found", argName)
}
