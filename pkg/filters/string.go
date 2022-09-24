package filters

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type StringFilter struct {
	Equal    []string
	NotEqual []string
	Size     uint
	Enabled  bool
}

func (filter *StringFilter) Parse(operatorAndValues string) error {
	filter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, values[i])
		case "!=":
			filter.NotEqual = append(filter.NotEqual, values[i])
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *StringFilter) InitBPF(bpfModule *bpf.Module, filterMapName string, filterScopeID uint32) error {
	if !filter.Enabled {
		return nil
	}

	// 1. uts_ns_filter     string[MAX_STR_FILTER_SIZE], u32    // filter events by uts namespace name
	// 2. comm_filter       string[MAX_STR_FILTER_SIZE], u32    // filter events by command name
	filterMap, err := bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	filterVal := make([]byte, 8)

	for i := 0; i < len(filter.Equal); i++ {
		filterEqualBytes := make([]byte, filter.Size)
		copy(filterEqualBytes, filter.Equal[i])

		var validBits uint32
		curVal, err := filterMap.GetValue(unsafe.Pointer(&filterEqualBytes[0]))
		if err == nil {
			validBits = binary.LittleEndian.Uint32(curVal[4:8])
		}
		binary.LittleEndian.PutUint32(filterVal[0:4], uint32(filterEqual))          // bitmask
		binary.LittleEndian.PutUint32(filterVal[4:8], validBits|(1<<filterScopeID)) // valid_bits
		if err = filterMap.Update(unsafe.Pointer(&filterEqualBytes[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		filterNotEqualBytes := make([]byte, filter.Size)
		copy(filterNotEqualBytes, filter.NotEqual[i])

		var validBits uint32
		curVal, err := filterMap.GetValue(unsafe.Pointer(&filterNotEqualBytes[0]))
		if err == nil {
			validBits = binary.LittleEndian.Uint32(curVal[4:8])
		}
		binary.LittleEndian.PutUint32(filterVal[0:4], uint32(filterNotEqual))       // bitmask
		binary.LittleEndian.PutUint32(filterVal[4:8], validBits|(1<<filterScopeID)) // valid_bits
		if err = filterMap.Update(unsafe.Pointer(&filterNotEqualBytes[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return err
		}
	}

	return nil
}

func (filter *StringFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		return false
	} else {
		return true
	}
}
