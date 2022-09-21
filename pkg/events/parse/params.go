package parse

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

func ArgInt32Val(event *trace.Event, argName string) (int32, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(int32)
			if !ok {
				return 0, fmt.Errorf("argument %s is not of type int32", argName)
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("argument %s not found", argName)
}

func ArgStringVal(event *trace.Event, argName string) (string, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(string)
			if !ok {
				return "", fmt.Errorf("argument %s is not of type string", argName)
			}
			return val, nil
		}
	}
	return "", fmt.Errorf("argument %s not found", argName)
}

func ArgUint64Val(event *trace.Event, argName string) (uint64, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(uint64)
			if !ok {
				return 0, fmt.Errorf("argument %s is not of type uint64", argName)
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("argument %s not found", argName)
}

func ArgInt64Val(event *trace.Event, argName string) (int64, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(int64)
			if !ok {
				return 0, fmt.Errorf("argument %s is not of type int64", argName)
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("argument %s not found", argName)
}

func ArgUint32Val(event *trace.Event, argName string) (uint32, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(uint32)
			if !ok {
				return 0, fmt.Errorf("argument %s is not of type uint32", argName)
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("argument %s not found", argName)
}

func ArgStringArrVal(event *trace.Event, argName string) ([]string, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.([]string)
			if !ok {
				return nil, fmt.Errorf("argument %s is not of type string", argName)
			}
			return val, nil
		}
	}
	return nil, fmt.Errorf("argument %s not found", argName)
}

func ArgUlongArrVal(event *trace.Event, argName string) ([]uint64, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.([]uint64)
			if !ok {
				return nil, fmt.Errorf("argument %s is not of type ulong array", argName)
			}
			return val, nil
		}
	}
	return nil, fmt.Errorf("argument %s not found", argName)
}

func ArgBoolVal(event *trace.Event, argName string) (bool, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			val, ok := arg.Value.(bool)
			if !ok {
				return false, fmt.Errorf("argument %s is not of type bool", argName)
			}
			return val, nil
		}
	}
	return false, fmt.Errorf("argument %s not found", argName)
}
