package filters

import (
	"fmt"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type StringFilter struct {
	Equal    []string
	NotEqual []string
	Enabled  bool
}

func NewStringFilter() *StringFilter {
	return &StringFilter{
		Equal:    []string{},
		NotEqual: []string{},
		Enabled:  false,
	}
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

type BPFStringFilter struct {
	StringFilter
	mapName string
}

func NewBPFStringFilter(mapName string) *BPFStringFilter {
	return &BPFStringFilter{
		StringFilter: *NewStringFilter(),
		mapName:      mapName,
	}
}

func (filter *BPFStringFilter) InitBPF(bpfModule *bpf.Module) error {
	// MaxBpfStrFilterSize value should match MAX_STR_FILTER_SIZE defined in BPF code
	const maxBpfStrFilterSize = 16

	if !filter.Enabled {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	// 1. uts_ns_filter     string[MAX_STR_FILTER_SIZE], u32    // filter events by uts namespace name
	// 2. comm_filter       string[MAX_STR_FILTER_SIZE], u32    // filter events by command name
	filterMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		filterEqualBytes := make([]byte, maxBpfStrFilterSize)
		copy(filterEqualBytes, filter.Equal[i])
		if err = filterMap.Update(unsafe.Pointer(&filterEqualBytes[0]), unsafe.Pointer(&filterEqualU32)); err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		filterNotEqualBytes := make([]byte, maxBpfStrFilterSize)
		copy(filterNotEqualBytes, filter.NotEqual[i])
		if err = filterMap.Update(unsafe.Pointer(&filterNotEqualBytes[0]), unsafe.Pointer(&filterNotEqualU32)); err != nil {
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
