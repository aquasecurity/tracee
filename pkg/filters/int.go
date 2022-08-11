package filters

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	maxNotSetInt int64 = math.MinInt64
	minNotSetInt int64 = math.MaxInt64
)

type IntFilter struct {
	equal    map[int64]bool
	notEqual map[int64]bool
	min      int64
	max      int64
	is32Bit  bool
	enabled  bool
}

func NewIntFilter() *IntFilter {
	return newIntFilter(false)
}

func NewInt32Filter() *IntFilter {
	return newIntFilter(true)
}

func newIntFilter(is32Bit bool) *IntFilter {
	filter := &IntFilter{
		equal:    map[int64]bool{},
		notEqual: map[int64]bool{},
		min:      minNotSetInt,
		max:      maxNotSetInt,
		is32Bit:  is32Bit,
	}

	return filter
}

func (f *IntFilter) Enable() {
	f.enabled = true
}

func (f *IntFilter) Disable() {
	f.enabled = false
}

func (f *IntFilter) Enabled() bool {
	return f.enabled
}

func (f *IntFilter) Minimum() int64 {
	return f.min
}

func (f *IntFilter) Maximum() int64 {
	return f.max
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *IntFilter) Filter(val int64) bool {
	result := !f.enabled || f.equal[val] || val > f.min || val < f.max
	if !result && f.notEqual[val] {
		return false
	}
	return result
}

func (f *IntFilter) validate(val int64) bool {
	if f.is32Bit {
		return val <= math.MaxInt32 && val >= math.MinInt32
	}
	return true
}

func (f *IntFilter) addEqual(val int64) {
	f.equal[val] = true
}

func (f *IntFilter) addNotEqual(val int64) {
	f.notEqual[val] = true
}

func (f *IntFilter) addLesserThan(val int64) {
	// we want to have the highest max input
	if val > f.max {
		f.max = val
	}
}

func (f *IntFilter) addGreaterThan(val int64) {
	// we want to have the lowest min input
	if val < f.min {
		f.min = val
	}
}

func (f *IntFilter) add(val int64, operator Operator) error {
	if !f.validate(val) {
		return InvalidValue(fmt.Sprint(val))
	}
	switch operator {
	case Equal:
		f.addEqual(val)
	case NotEqual:
		f.addNotEqual(val)
	case Lower:
		f.addLesserThan(val)
	case Greater:
		f.addGreaterThan(val)
	case LowerEqual:
		f.addEqual(val)
		f.addLesserThan(val)
	case GreaterEqual:
		f.addEqual(val)
		f.addGreaterThan(val)
	}
	return nil
}

func (filter *IntFilter) Parse(operatorAndValues string) error {
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
		valInt, err := strconv.ParseInt(val, 10, 64)
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
