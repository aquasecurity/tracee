package filters

import (
	"fmt"
	"math"
	"strconv"

	"github.com/aquasecurity/tracee/types/protocol"
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

func NewIntFilter(filters ...protocol.Filter) (*IntFilter, error) {
	return newIntFilter(false, filters...)
}

func NewInt32Filter(filters ...protocol.Filter) (*IntFilter, error) {
	return newIntFilter(true, filters...)
}

func newIntFilter(is32Bit bool, filters ...protocol.Filter) (*IntFilter, error) {
	filter := &IntFilter{
		equal:    map[int64]bool{},
		notEqual: map[int64]bool{},
		min:      minNotSetInt,
		max:      maxNotSetInt,
		is32Bit:  is32Bit,
	}

	for _, f := range filters {
		err := filter.parse(f)
		if err != nil {
			return filter, err
		}
	}

	if len(filters) > 0 {
		filter.Enable()
	}

	return filter, nil
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
		return fmt.Errorf("filter value %d is unsupported", val)
	}
	switch operator {
	case Equal:
		f.addEqual(val)
	case NotEqual:
		f.addNotEqual(val)
	case Lesser:
		f.addLesserThan(val)
	case Greater:
		f.addGreaterThan(val)
	case LesserEqual:
		f.addEqual(val)
		f.addLesserThan(val)
	case GreaterEqual:
		f.addEqual(val)
		f.addGreaterThan(val)
	}
	return nil
}

func (f *IntFilter) parse(filterReq protocol.Filter) error {
	for _, val := range filterReq.Value {
		val := fmt.Sprintf("%v", val)
		valInt, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to add to filter: invalid value: %v", val)
		}
		err = f.add(valInt, Operator(filterReq.Operator))
		if err != nil {
			return fmt.Errorf("failed to build filter: %s", err)
		}
	}
	return nil
}
