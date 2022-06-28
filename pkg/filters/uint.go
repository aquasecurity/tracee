package filters

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type UIntFilter struct {
	Equal    []uint64
	NotEqual []uint64
	Greater  uint64
	Less     uint64
	Is32Bit  bool
	Enabled  bool
}

func (filter *UIntFilter) Parse(operatorAndValues string) error {
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
		val, err := strconv.ParseUint(values[i], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid filter value: %s", values[i])
		}
		if filter.Is32Bit && (val > math.MaxUint32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, val)
		case "!=":
			filter.NotEqual = append(filter.NotEqual, val)
		case ">":
			if (filter.Greater == GreaterNotSetUint) || (val > filter.Greater) {
				filter.Greater = val
			}
		case "<":
			if (filter.Less == LessNotSetUint) || (val < filter.Less) {
				filter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *UIntFilter) InitBPF(bpfModule *bpf.Module, filterMapName string) error {
	if !filter.Enabled {
		return nil
	}

	// equalityFilter filters events for given maps:
	// 1. uid_filter        u32, u32
	// 2. pid_filter        u32, u32
	// 3. mnt_ns_filter     u64, u32
	// 4. pid_ns_filter     u64, u32
	equalityFilter, err := bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		// todo: prepare for ALL filters on a local map, then update in tracee.go
		filterVal := make([]byte, 8)
		binary.LittleEndian.PutUint32(filterVal[0:4], uint32(filterEqual))
		binary.LittleEndian.PutUint32(filterVal[4:8], uint32(1))
		if filter.Is32Bit {
			EqualU32 := uint32(filter.Equal[i])
			err = equalityFilter.Update(unsafe.Pointer(&EqualU32), unsafe.Pointer(&filterVal[0]))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.Equal[i]), unsafe.Pointer(&filterVal[0]))
		}
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		filterVal := make([]byte, 8)
		binary.LittleEndian.PutUint32(filterVal[0:4], uint32(filterNotEqual))
		binary.LittleEndian.PutUint32(filterVal[4:8], uint32(1))
		if filter.Is32Bit {
			NotEqualU32 := uint32(filter.NotEqual[i])
			err = equalityFilter.Update(unsafe.Pointer(&NotEqualU32), unsafe.Pointer(&filterVal[0]))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.NotEqual[i]), unsafe.Pointer(&filterVal[0]))
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (filter *UIntFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 && filter.Greater == GreaterNotSetUint && filter.Less == LessNotSetUint {
		return false
	} else {
		return true
	}
}
