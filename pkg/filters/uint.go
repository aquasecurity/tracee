package filters

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	MaxNotSetUInt uint64 = 0
	MinNotSetUInt uint64 = math.MaxUint64
)

type UIntFilter[T constraints.Unsigned] struct {
	equal    map[uint64]struct{}
	notEqual map[uint64]struct{}
	min      uint64
	max      uint64
	is32Bit  bool
	enabled  bool
}

// Compile-time check to ensure that UIntFilter implements the Cloner interface
var _ utils.Cloner[*UIntFilter[uint32]] = &UIntFilter[uint32]{}

// TODO: Add uint16 and uint8 filters?

func NewUIntFilter() *UIntFilter[uint64] {
	return newUIntFilter[uint64](false)
}

func NewUInt32Filter() *UIntFilter[uint32] {
	return newUIntFilter[uint32](true)
}

func newUIntFilter[T constraints.Unsigned](is32Bit bool) *UIntFilter[T] {
	return &UIntFilter[T]{
		equal:    map[uint64]struct{}{},
		notEqual: map[uint64]struct{}{},
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
	_, inEqual := f.equal[compVal]
	_, inNotEqual := f.notEqual[compVal]

	result := !f.enabled || inEqual || compVal > f.min || compVal < f.max
	if !result && inNotEqual {
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
	f.equal[val] = struct{}{}
}

func (f *UIntFilter[T]) addNotEqual(val uint64) {
	f.notEqual[val] = struct{}{}
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

func (f *UIntFilter[T]) Parse(operatorAndValues string) error {
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
		err = f.add(valInt, operator)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	f.Enable()

	return nil
}

func (f *UIntFilter[T]) FilterOut() bool {
	if len(f.equal) > 0 && len(f.notEqual) == 0 && f.min == MinNotSetUInt && f.max == MaxNotSetUInt {
		return false
	}
	return true
}

type UIntFilterEqualities struct {
	Equal    map[uint64]struct{}
	NotEqual map[uint64]struct{}
}

func (f *UIntFilter[T]) Equalities() UIntFilterEqualities {
	if !f.Enabled() {
		return UIntFilterEqualities{
			Equal:    map[uint64]struct{}{},
			NotEqual: map[uint64]struct{}{},
		}
	}

	return UIntFilterEqualities{
		Equal:    maps.Clone(f.equal),
		NotEqual: maps.Clone(f.notEqual),
	}
}

func (f *UIntFilter[T]) Clone() *UIntFilter[T] {
	if f == nil {
		return nil
	}

	n := newUIntFilter[T](f.is32Bit)

	maps.Copy(n.equal, f.equal)
	maps.Copy(n.notEqual, f.notEqual)
	n.min = f.min
	n.max = f.max
	n.enabled = f.enabled

	return n
}
