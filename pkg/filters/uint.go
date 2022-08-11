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
	maxNotSetUInt uint64 = 0
	minNotSetUInt uint64 = math.MaxUint64
)

type UIntFilter struct {
	equal    map[uint64]bool
	notEqual map[uint64]bool
	min      uint64
	max      uint64
	is32Bit  bool
	enabled  bool
}

func NewUIntFilter() *UIntFilter {
	return newUIntFilter(false)
}

func NewUInt32Filter() *UIntFilter {
	return newUIntFilter(true)
}

func newUIntFilter(is32Bit bool) *UIntFilter {
	return &UIntFilter{
		equal:    map[uint64]bool{},
		notEqual: map[uint64]bool{},
		min:      minNotSetUInt,
		max:      maxNotSetUInt,
		is32Bit:  is32Bit,
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
	return f.min
}

func (f *UIntFilter) Maximum() uint64 {
	return f.max
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *UIntFilter) Filter(val uint64) bool {
	result := !f.Enabled() || f.equal[val] || val > f.min || val < f.max
	if !result && f.notEqual[val] {
		return false
	}
	return result
}

func (f *UIntFilter) validate(val uint64) bool {
	const maxUIntVal32Bit = math.MaxUint32
	if f.is32Bit {
		return val <= maxUIntVal32Bit
	}
	return true
}

func (f *UIntFilter) addEqual(val uint64) {
	f.equal[val] = true
}

func (f *UIntFilter) addNotEqual(val uint64) {
	f.notEqual[val] = true
}

func (f *UIntFilter) addLessThan(val uint64) {
	// we want to have the highest max input
	if val > f.max {
		f.max = val
	}
}

func (f *UIntFilter) addGreaterThan(val uint64) {
	// we want to have the lowest min input
	if val < f.min {
		f.min = val
	}
}

func (f *UIntFilter) add(val uint64, operator Operator) error {
	if !f.validate(val) {
		return InvalidValue(fmt.Sprint(val))
	}
	switch operator {
	case Equal:
		f.addEqual(val)
	case NotEqual:
		f.addNotEqual(val)
	case Lower:
		f.addLessThan(val)
	case Greater:
		f.addGreaterThan(val)
	case LowerEqual:
		f.addEqual(val)
		f.addLessThan(val)
	case GreaterEqual:
		f.addEqual(val)
		f.addGreaterThan(val)
	}
	return nil
}

func (filter *UIntFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return InvalidExpression(operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	// check for !=
	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return InvalidExpression(operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	// check for >= and <=
	if (operatorString == ">" || operatorString == "<") && operatorAndValues[1] == '=' {
		if len(operatorAndValues) < 3 {
			return InvalidExpression(operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")
	operator := stringToOperator(operatorString)

	for _, val := range values {
		valInt, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return InvalidValue(val)
		}
		err = filter.add(valInt, operator)
		if err != nil {
			return err
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

	bpfFilterEqual := uint32(filterEqual) // const need local var for bpfMap.Update()
	bpfFilterNotEqual := uint32(filterNotEqual)

	// equalityFilter filters events for given maps:
	// 1. uid_filter        u32, u32
	// 2. pid_filter        u32, u32
	// 3. mnt_ns_filter     u64, u32
	// 4. pid_ns_filter     u64, u32
	equalityFilterMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return err
	}

	for equalFilter := range filter.equal {
		if filter.is32Bit {
			equalU32 := uint32(equalFilter)
			err = equalityFilterMap.Update(unsafe.Pointer(&equalU32), unsafe.Pointer(&bpfFilterEqual))
		} else {
			err = equalityFilterMap.Update(unsafe.Pointer(&equalFilter), unsafe.Pointer(&bpfFilterEqual))
		}
		if err != nil {
			return err
		}
	}
	for notEqualFilter := range filter.notEqual {
		if filter.is32Bit {
			notEqualU32 := uint32(notEqualFilter)
			err = equalityFilterMap.Update(unsafe.Pointer(&notEqualU32), unsafe.Pointer(&bpfFilterNotEqual))
		} else {
			err = equalityFilterMap.Update(unsafe.Pointer(&notEqualFilter), unsafe.Pointer(&bpfFilterNotEqual))
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (filter *UIntFilter) FilterOut() bool {
	if len(filter.equal) > 0 && len(filter.notEqual) == 0 && filter.min == minNotSetUInt && filter.max == maxNotSetUInt {
		return false
	} else {
		return true
	}
}
