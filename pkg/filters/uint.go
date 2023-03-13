package filters

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/exp/constraints"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	MaxNotSetUInt uint64 = 0
	MinNotSetUInt uint64 = math.MaxUint64
)

type UIntFilter[T constraints.Unsigned] struct {
	equal    map[uint64]bool
	notEqual map[uint64]bool
	min      uint64
	max      uint64
	is32Bit  bool
	enabled  bool
}

// TODO: Add uint16 and uint8 filters?

func NewUIntFilter() *UIntFilter[uint64] {
	return newUIntFilter[uint64](false)
}

func NewUInt32Filter() *UIntFilter[uint32] {
	return newUIntFilter[uint32](true)
}

func newUIntFilter[T constraints.Unsigned](is32Bit bool) *UIntFilter[T] {
	return &UIntFilter[T]{
		equal:    map[uint64]bool{},
		notEqual: map[uint64]bool{},
		min:      MinNotSetUInt,
		max:      MaxNotSetUInt,
		is32Bit:  is32Bit,
	}
}

func (f *UIntFilter[T]) Enable() {
	f.enabled = true
}

func (f *UIntFilter[T]) Disable() {
	f.enabled = false
}

func (f *UIntFilter[T]) Enabled() bool {
	return f.enabled
}

func (f *UIntFilter[T]) Minimum() uint64 {
	return f.min
}

func (f *UIntFilter[T]) Maximum() uint64 {
	return f.max
}

func (f *UIntFilter[T]) Filter(val interface{}) bool {
	filterable, ok := val.(T)
	if !ok {
		return false
	}
	return f.filter(filterable)
}

func (f UIntFilter[T]) InMinMaxRange(val T) bool {
	if f.min == MinNotSetUInt && f.max == MaxNotSetUInt {
		return true
	}

	v := uint64(val)
	if f.min == MinNotSetUInt {
		return v < f.max
	}
	if f.max == MaxNotSetUInt {
		return v > f.min
	}

	return v > f.min && v < f.max
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *UIntFilter[T]) filter(val T) bool {
	compVal := uint64(val)
	result := !f.Enabled() || f.equal[compVal] || compVal > f.min || compVal < f.max
	if !result && f.notEqual[compVal] {
		return false
	}
	return result
}

func (f *UIntFilter[T]) validate(val uint64) bool {
	const maxUIntVal32Bit = math.MaxUint32
	if f.is32Bit {
		return val <= maxUIntVal32Bit
	}
	return true
}

func (f *UIntFilter[T]) addEqual(val uint64) {
	f.equal[val] = true
}

func (f *UIntFilter[T]) addNotEqual(val uint64) {
	f.notEqual[val] = true
}

func (f *UIntFilter[T]) addLessThan(val uint64) {
	// we want to have the highest max input
	if val > f.max {
		f.max = val
	}
}

func (f *UIntFilter[T]) addGreaterThan(val uint64) {
	// we want to have the lowest min input
	if val < f.min {
		f.min = val
	}
}

func (f *UIntFilter[T]) add(val uint64, operator Operator) error {
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

func (filter *UIntFilter[T]) Parse(operatorAndValues string) error {
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
		// 'uint<0'
		if operator == Lower && valInt == 0 {
			return InvalidExpression(operatorAndValues)
		}
		err = filter.add(valInt, operator)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	filter.Enable()

	return nil
}

type BPFUIntFilter[T constraints.Unsigned] struct {
	UIntFilter[T]
	mapName string
}

func NewBPFUIntFilter(mapName string) *BPFUIntFilter[uint64] {
	return &BPFUIntFilter[uint64]{
		UIntFilter: *NewUIntFilter(),
		mapName:    mapName,
	}
}

func NewBPFUInt32Filter(mapName string) *BPFUIntFilter[uint32] {
	return &BPFUIntFilter[uint32]{
		UIntFilter: *NewUInt32Filter(),
		mapName:    mapName,
	}
}

func (filter *BPFUIntFilter[T]) UpdateBPF(bpfModule *bpf.Module, policyID uint) error {
	if !filter.Enabled() {
		return nil
	}

	// equalityFilter filters events for given maps:
	// 1. uid_filter        u32, eq_t
	// 2. pid_filter        u32, eq_t
	// 3. mnt_ns_filter     u64, eq_t
	// 4. pid_ns_filter     u64, eq_t
	equalityFilterMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	var keyPointer unsafe.Pointer
	filterVal := make([]byte, 16)

	// first initialize notEqual values since equality should take precedence
	for notEqualFilter := range filter.notEqual {
		notEqualU32 := uint32(notEqualFilter)
		if filter.is32Bit {
			keyPointer = unsafe.Pointer(&notEqualU32)
		} else {
			keyPointer = unsafe.Pointer(&notEqualFilter)
		}

		var equalInPolicies, equalitySetInPolicies uint64
		curVal, err := equalityFilterMap.GetValue(keyPointer)
		if err == nil {
			equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
		}

		// filterNotEqual == 0, so clear n bitmask bit
		utils.ClearBit(&equalInPolicies, policyID)
		utils.SetBit(&equalitySetInPolicies, policyID)

		binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
		err = equalityFilterMap.Update(unsafe.Pointer(keyPointer), unsafe.Pointer(&filterVal[0]))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// now - setup equality filters
	for equalFilter := range filter.equal {
		equalU32 := uint32(equalFilter)
		if filter.is32Bit {
			keyPointer = unsafe.Pointer(&equalU32)
		} else {
			keyPointer = unsafe.Pointer(&equalFilter)
		}

		var equalInPolicies, equalitySetInPolicies uint64
		curVal, err := equalityFilterMap.GetValue(keyPointer)
		if err == nil {
			equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
		}

		// filterEqual == 1, so set n bitmask bit
		utils.SetBit(&equalInPolicies, policyID)
		utils.SetBit(&equalitySetInPolicies, policyID)

		binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
		err = equalityFilterMap.Update(unsafe.Pointer(keyPointer), unsafe.Pointer(&filterVal[0]))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

func (filter *UIntFilter[T]) FilterOut() bool {
	if len(filter.equal) > 0 && len(filter.notEqual) == 0 && filter.min == MinNotSetUInt && filter.max == MaxNotSetUInt {
		return false
	} else {
		return true
	}
}
