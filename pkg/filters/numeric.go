package filters

import (
	"math"
	"strconv"
	"strings"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/utils"
)

// NumericConstraint defines the constraint for numeric types that can be filtered
type NumericConstraint interface {
	constraints.Signed | constraints.Unsigned
}

// NumericFilter is a generic filter for both signed and unsigned numeric types
type NumericFilter[T NumericConstraint] struct {
	equal    map[T]struct{}
	notEqual map[T]struct{}
	min      T
	max      T
	// Pre-computed unset values for performance
	unsetMin T
	unsetMax T
	is32Bit  bool
	enabled  bool
}

// Compile-time checks to ensure NumericFilter implements the Cloner interface
var _ utils.Cloner[*NumericFilter[int32]] = &NumericFilter[int32]{}
var _ utils.Cloner[*NumericFilter[uint32]] = &NumericFilter[uint32]{}
var _ utils.Cloner[*NumericFilter[int64]] = &NumericFilter[int64]{}
var _ utils.Cloner[*NumericFilter[uint64]] = &NumericFilter[uint64]{}

// GetUnsetMin returns the "unset" minimum value for numeric type T.
// For unsigned types, this is the maximum value (indicating no minimum constraint).
// For signed types, this is the maximum value (indicating no minimum constraint).
func GetUnsetMin[T NumericConstraint]() T {
	var zero T
	switch any(zero).(type) {
	case uint32:
		if val, ok := any(^uint32(0)).(T); ok {
			return val
		}
	case uint64:
		if val, ok := any(^uint64(0)).(T); ok {
			return val
		}
	case int32:
		if val, ok := any(int32(math.MaxInt32)).(T); ok {
			return val
		}
	case int64:
		if val, ok := any(int64(math.MaxInt64)).(T); ok {
			return val
		}
	}
	return zero
}

// GetUnsetMax returns the "unset" maximum value for numeric type T.
// For unsigned types, this is zero (indicating no maximum constraint).
// For signed types, this is the minimum value (indicating no maximum constraint).
func GetUnsetMax[T NumericConstraint]() T {
	var zero T
	switch any(zero).(type) {
	case uint32:
		if val, ok := any(uint32(0)).(T); ok {
			return val
		}
	case uint64:
		if val, ok := any(uint64(0)).(T); ok {
			return val
		}
	case int32:
		if val, ok := any(int32(math.MinInt32)).(T); ok {
			return val
		}
	case int64:
		if val, ok := any(int64(math.MinInt64)).(T); ok {
			return val
		}
	}
	return zero
}

// isUnsignedType returns true if T is an unsigned integer type
func isUnsignedType[T NumericConstraint]() bool {
	var zero T
	_, isUint64 := any(zero).(uint64)
	_, isUint32 := any(zero).(uint32)
	return isUint64 || isUint32
}

// is32BitType returns true if T is a 32-bit integer type
func is32BitType[T NumericConstraint]() bool {
	var zero T
	_, isUint32 := any(zero).(uint32)
	_, isInt32 := any(zero).(int32)
	return isUint32 || isInt32
}

// NewNumericFilter creates a new generic numeric filter for the specified type
func NewNumericFilter[T NumericConstraint]() *NumericFilter[T] {
	return newNumericFilter[T](is32BitType[T]())
}

// Constructor helpers for backward compatibility
func NewIntFilter() *NumericFilter[int64] {
	return NewNumericFilter[int64]()
}

func NewInt32Filter() *NumericFilter[int32] {
	return NewNumericFilter[int32]()
}

func NewUIntFilter() *NumericFilter[uint64] {
	return NewNumericFilter[uint64]()
}

func NewUInt32Filter() *NumericFilter[uint32] {
	return NewNumericFilter[uint32]()
}

func newNumericFilter[T NumericConstraint](is32Bit bool) *NumericFilter[T] {
	unsetMin := GetUnsetMin[T]()
	unsetMax := GetUnsetMax[T]()
	return &NumericFilter[T]{
		equal:    map[T]struct{}{},
		notEqual: map[T]struct{}{},
		min:      unsetMin,
		max:      unsetMax,
		unsetMin: unsetMin, // Store for fast comparison
		unsetMax: unsetMax, // Store for fast comparison
		is32Bit:  is32Bit,
	}
}

func (f *NumericFilter[T]) Enable() {
	f.enabled = true
}

func (f *NumericFilter[T]) Disable() {
	f.enabled = false
}

func (f *NumericFilter[T]) Enabled() bool {
	return f.enabled
}

func (f *NumericFilter[T]) Minimum() T {
	return f.min
}

func (f *NumericFilter[T]) Maximum() T {
	return f.max
}

// Filter checks if the given value matches the filter criteria.
// Returns false if val is not of type T or doesn't match the filter conditions.
// The filter uses priority: equality > range constraints > not-equality.
func (f *NumericFilter[T]) Filter(val any) bool {
	filterable, ok := val.(T)
	if !ok {
		return false
	}
	return f.filter(filterable)
}

// InMinMaxRange checks if a value is within the configured min/max range.
// Returns true if no range constraints are set, or if val is within the range.
// Range checks are exclusive: val must be > min and < max.
func (f *NumericFilter[T]) InMinMaxRange(val T) bool {
	if f.min == f.unsetMin && f.max == f.unsetMax {
		return true
	}

	if f.min == f.unsetMin {
		return val < f.max
	}
	if f.max == f.unsetMax {
		return val > f.min
	}

	return val > f.min && val < f.max
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *NumericFilter[T]) filter(val T) bool {
	_, inEqual := f.equal[val]
	_, inNotEqual := f.notEqual[val]

	// If disabled, allow everything
	if !f.enabled {
		return true
	}

	// Check equality first (highest priority)
	if inEqual {
		return true
	}

	// Check not-equal (reject if found)
	if inNotEqual {
		return false
	}

	// Check range constraints using the same logic as InMinMaxRange()
	// Only check range constraints if they are set
	if f.min != f.unsetMin || f.max != f.unsetMax {
		return f.InMinMaxRange(val)
	}

	// No constraints set - if filter is enabled but no conditions, reject everything
	// This matches the original behavior where enabled but empty filter rejects all
	return false
}

func (f *NumericFilter[T]) addEqual(val T) {
	f.equal[val] = struct{}{}
}

func (f *NumericFilter[T]) addNotEqual(val T) {
	f.notEqual[val] = struct{}{}
}

func (f *NumericFilter[T]) addLessThan(val T) {
	// we want to have the highest max input
	if val > f.max {
		f.max = val
	}
}

func (f *NumericFilter[T]) addGreaterThan(val T) {
	// we want to have the lowest min input
	if val < f.min {
		f.min = val
	}
}

func (f *NumericFilter[T]) add(val T, operator Operator) {
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
}

// Parse parses a filter expression and adds the constraints to the filter.
// Supported operators: =, !=, <, <=, >, >=
// Values can be comma-separated for multiple constraints with the same operator.
// Examples: "=1,2,3", ">10", "<=100", "!=5"
func (f *NumericFilter[T]) Parse(operatorAndValues string) error {
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
		var parsedVal T

		// Handle parsing based on whether this is a signed or unsigned type
		if isUnsignedType[T]() {
			valUint, parseErr := strconv.ParseUint(val, 10, 64)
			if parseErr != nil {
				return InvalidValue(val)
			}
			// Check for invalid unsigned operation: 'uint<0'
			if operator == Lower && valUint == 0 {
				return InvalidExpression(operatorAndValues)
			}

			// Validate range for 32-bit unsigned types
			var zero T
			if _, isUint32 := any(zero).(uint32); isUint32 && valUint > math.MaxUint32 {
				return InvalidValue(val)
			}

			parsedVal = T(valUint)
		} else {
			valInt, parseErr := strconv.ParseInt(val, 10, 64)
			if parseErr != nil {
				return InvalidValue(val)
			}

			// Validate range for 32-bit signed types
			var zero T
			if _, isInt32 := any(zero).(int32); isInt32 && (valInt > math.MaxInt32 || valInt < math.MinInt32) {
				return InvalidValue(val)
			}

			parsedVal = T(valInt)
		}

		f.add(parsedVal, operator)
	}

	f.Enable()
	return nil
}

// MatchIfKeyMissing returns whether missing keys should match the filter.
// Returns false only when the filter has equality constraints but no other constraints.
func (f *NumericFilter[T]) MatchIfKeyMissing() bool {
	if len(f.equal) > 0 && len(f.notEqual) == 0 && f.min == f.unsetMin && f.max == f.unsetMax {
		return false
	}
	return true
}

// NumericFilterEqualities represents the equality maps for any numeric type T
type NumericFilterEqualities[T NumericConstraint] struct {
	Equal    map[T]struct{}
	NotEqual map[T]struct{}
}

// Equalities returns the equality maps with the exact type T.
// Returns empty maps if the filter is disabled.
func (f *NumericFilter[T]) Equalities() NumericFilterEqualities[T] {
	if !f.Enabled() {
		return NumericFilterEqualities[T]{
			Equal:    map[T]struct{}{},
			NotEqual: map[T]struct{}{},
		}
	}

	return NumericFilterEqualities[T]{
		Equal:    maps.Clone(f.equal),
		NotEqual: maps.Clone(f.notEqual),
	}
}

func (f *NumericFilter[T]) Clone() *NumericFilter[T] {
	if f == nil {
		return nil
	}

	n := newNumericFilter[T](f.is32Bit)

	maps.Copy(n.equal, f.equal)
	maps.Copy(n.notEqual, f.notEqual)
	n.min = f.min
	n.max = f.max
	n.enabled = f.enabled
	// unsetMin and unsetMax are already set by newNumericFilter

	return n
}
