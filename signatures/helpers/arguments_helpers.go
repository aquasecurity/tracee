package helpers

import (
	b64 "encoding/base64"
	"errors"
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

func ArgVal[T any](args []trace.Argument, argName string) (T, error) {
	for _, arg := range args {
		if arg.Name == argName {
			val, ok := arg.Value.(T)
			if !ok {
				zeroVal := *new(T)
				return zeroVal, fmt.Errorf(
					"argument %s is not of type %T, is of type %T",
					argName,
					zeroVal,
					arg.Value,
				)
			}
			return val, nil
		}
	}
	return *new(T), fmt.Errorf("argument %s not found", argName)
}

// GetArgOps represents options for arguments getters
type GetArgOps struct {
	DefaultArgs bool // Receive default args value (value equals 'nil'). If set to false, will return error if arg not initialized.
}

// GetTraceeArgumentByName fetches the argument in event with `Name` that matches argName
func GetTraceeArgumentByName(event trace.Event, argName string, opts GetArgOps) (trace.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			if !opts.DefaultArgs && arg.Value == nil {
				return arg, fmt.Errorf("argument %s is not initialized", argName)
			}
			return arg, nil
		}
	}
	return trace.Argument{}, fmt.Errorf("argument %s not found", argName)
}

// GetTraceeStringArgumentByName retrieves the argument from the event's "Args" field
// that matches the specified "argName". The argument value is returned cast as a string.
func GetTraceeStringArgumentByName(event trace.Event, argName string) (string, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return "", err
	}
	argStr, ok := arg.Value.(string)
	if ok {
		return argStr, nil
	}

	return "", fmt.Errorf("can't convert argument %v to string", argName)
}

// GetTraceeIntArgumentByName retrieves the argument from the event's "Args" field
// that matches the specified "argName". The argument value is returned cast as a int.
func GetTraceeIntArgumentByName(event trace.Event, argName string) (int, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return 0, err
	}

	argInt32, ok := arg.Value.(int32)
	if ok {
		return int(argInt32), nil
	}
	argInt64, ok := arg.Value.(int64)
	if ok {
		return int(argInt64), nil
	}
	argInt, ok := arg.Value.(int)
	if ok {
		return argInt, nil
	}

	return 0, fmt.Errorf("can't convert argument %v to int (argument is of type %T)", argName, arg.Value)
}

// GetTraceeUIntArgumentByName gets the argument matching the "argName" given from the event "argv" field, casted as int.
func GetTraceeUintArgumentByName(event trace.Event, argName string) (uint, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return 0, err
	}

	argUint32, ok := arg.Value.(uint32)
	if ok {
		return uint(argUint32), nil
	}
	argUint64, ok := arg.Value.(uint64)
	if ok {
		return uint(argUint64), nil
	}
	argUint, ok := arg.Value.(uint)
	if ok {
		return argUint, nil
	}

	return 0, fmt.Errorf("can't convert argument %v to int (argument is of type %T)", argName, arg.Value)
}

// GetTraceeSliceStringArgumentByName retrieves the argument from the event's "Args" field
// that matches the specified "argName". The argument value is returned cast as a []string.
func GetTraceeSliceStringArgumentByName(event trace.Event, argName string) ([]string, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}
	argStr, ok := arg.Value.([]string)
	if ok {
		return argStr, nil
	}

	return nil, fmt.Errorf("can't convert argument %v to slice of strings", argName)
}

// GetTraceeBytesSliceArgumentByName retrieves the argument from the event's "Args" field
// that matches the specified "argName". The argument value is returned cast as a []byte.
func GetTraceeBytesSliceArgumentByName(event trace.Event, argName string) ([]byte, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}
	argBytes, ok := arg.Value.([]byte)
	if ok {
		return argBytes, nil
	}

	argBytesString, ok := arg.Value.(string)
	if ok {
		decodedBytes, err := b64.StdEncoding.DecodeString(argBytesString)
		if err != nil {
			return nil, fmt.Errorf("can't convert argument %v to []bytes", argName)
		}
		return decodedBytes, nil
	}

	return nil, fmt.Errorf("can't convert argument %v to []bytes", argName)
}

// GetRawAddrArgumentByName returns map[string]string of addr argument
func GetRawAddrArgumentByName(event trace.Event, argName string) (map[string]string, error) {
	arg, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil, err
	}
	addr, isOk := arg.Value.(map[string]string)
	if !isOk {
		addr = make(map[string]string)
		stringInterMap, isStringInterMap := arg.Value.(map[string]interface{})
		if !isStringInterMap {
			return addr, errors.New("couldn't convert arg to addr")
		}
		for k, v := range stringInterMap {
			s, isString := v.(string)
			if !isString {
				return addr, errors.New("couldn't convert arg to addr")
			}
			addr[k] = s
		}
	}

	return addr, nil
}

// GetTraceeHookedSymbolDataArgumentByName returns []trace.HookedSymbolData of hooked symbols for arg
func GetTraceeHookedSymbolDataArgumentByName(event trace.Event, argName string) ([]trace.HookedSymbolData, error) {
	hookedSymbolsPtr, err := GetTraceeArgumentByName(event, argName, GetArgOps{DefaultArgs: false})
	if err != nil {
		return []trace.HookedSymbolData{}, err
	}

	var hookedSymbols []trace.HookedSymbolData

	hookedSymbols, ok := hookedSymbolsPtr.Value.([]trace.HookedSymbolData)
	if ok {
		return hookedSymbols, nil
	}

	argSlice, ok := hookedSymbolsPtr.Value.([]interface{})
	if ok {
		for _, v := range argSlice {
			hookedSymbol, err := getHookedSymbolData(v)
			if err != nil {
				continue
			}
			hookedSymbols = append(hookedSymbols, hookedSymbol)
		}
		return hookedSymbols, nil
	}

	return hookedSymbols, fmt.Errorf("can't convert argument %v to []trace.HookedSymbolData", argName)
}

// getHookedSymbolData generates a trace.HookedSymbolData from interface{} got from event arg
func getHookedSymbolData(v interface{}) (trace.HookedSymbolData, error) {
	symbol := trace.HookedSymbolData{}

	hookedSymbolMap, ok := v.(map[string]interface{})
	if !ok {
		return symbol, errors.New("can't convert hooked symbol to map[string]interface{}")
	}

	for key, value := range hookedSymbolMap {
		strValue, ok := value.(string)
		if !ok {
			continue
		}
		switch key {
		case "ModuleOwner":
			symbol.ModuleOwner = strValue

		case "SymbolName":
			symbol.SymbolName = strValue
		}
	}

	return symbol, nil
}
