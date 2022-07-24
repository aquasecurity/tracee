package filters

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	minUIntVal uint64 = 0
	maxUIntVal uint64 = math.MaxUint64
)

type UIntFilter struct {
	Equal       []uint64
	NotEqual    []uint64
	GreaterThan uint64
	LessThan    uint64
	Is32Bit     bool
	enabled     bool
}

func NewUIntFilter() *UIntFilter {
	return newUIntFilter(false)
}

func NewUInt32Filter() *UIntFilter {
	return newUIntFilter(true)
}

func newUIntFilter(is32Bit bool) *UIntFilter {
	return &UIntFilter{
		Equal:       []uint64{},
		NotEqual:    []uint64{},
		GreaterThan: maxUIntVal,
		LessThan:    minUIntVal,
		Is32Bit:     is32Bit,
		enabled:     false,
	}
}

func (f *UIntFilter) Enable() {
	f.enabled = true
}

func (f *UIntFilter) Disable() {
	f.enabled = false
}

func (f *UIntFilter) Enabled() bool {
	return f.enabled
}

func (f *UIntFilter) Minimum() uint64 {
	return f.GreaterThan
}

func (f *UIntFilter) Maximum() uint64 {
	return f.LessThan
}

func (filter *UIntFilter) Parse(operatorAndValues string) error {
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
			if (filter.GreaterThan == maxUIntVal) || (val > filter.GreaterThan) {
				filter.GreaterThan = val
			}
		case "<":
			if (filter.LessThan == minUIntVal) || (val < filter.LessThan) {
				filter.LessThan = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	filter.Enable()

	return nil
}

type BPFUIntFilter struct {
	UIntFilter
	mapName string
}

func NewBPFUIntFilter(mapName string) *BPFUIntFilter {
	return &BPFUIntFilter{
		UIntFilter: *NewUIntFilter(),
		mapName:    mapName,
	}
}

func NewBPFUInt32Filter(mapName string) *BPFUIntFilter {
	return &BPFUIntFilter{
		UIntFilter: *NewUInt32Filter(),
		mapName:    mapName,
	}
}

func (filter *BPFUIntFilter) InitBPF(bpfModule *bpf.Module) error {
	if !filter.Enabled() {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	// equalityFilter filters events for given maps:
	// 1. uid_filter        u32, u32
	// 2. pid_filter        u32, u32
	// 3. mnt_ns_filter     u64, u32
	// 4. pid_ns_filter     u64, u32
	equalityFilter, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		if filter.Is32Bit {
			EqualU32 := uint32(filter.Equal[i])
			err = equalityFilter.Update(unsafe.Pointer(&EqualU32), unsafe.Pointer(&filterEqualU32))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.Equal[i]), unsafe.Pointer(&filterEqualU32))
		}
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		if filter.Is32Bit {
			NotEqualU32 := uint32(filter.NotEqual[i])
			err = equalityFilter.Update(unsafe.Pointer(&NotEqualU32), unsafe.Pointer(&filterNotEqualU32))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.NotEqual[i]), unsafe.Pointer(&filterNotEqualU32))
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (filter *UIntFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 && filter.GreaterThan == maxUIntVal && filter.LessThan == minUIntVal {
		return false
	} else {
		return true
	}
}
