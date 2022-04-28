package parsing

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

func GetEventArgInt32Val(event *trace.Event, argName string) (int32, error) {
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

func GetEventArgStringVal(event *trace.Event, argName string) (string, error) {
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

func GetEventArgUint64Val(event *trace.Event, argName string) (uint64, error) {
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

func GetEventArgUint32Val(event *trace.Event, argName string) (uint32, error) {
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

func GetEventArgStringArrVal(event *trace.Event, argName string) ([]string, error) {
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

func GetEventArgUlongArrVal(event *trace.Event, argName string) ([]uint64, error) {
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
