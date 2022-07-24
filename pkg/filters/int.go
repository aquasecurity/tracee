package filters

import (
	"fmt"
	"math"
	"strconv"

	"github.com/aquasecurity/tracee/types/protocol"
)

const (
	minIntVal int64 = math.MinInt64
	maxIntVal int64 = math.MaxInt64
)

type IntFilter struct {
	equal       map[int64]bool
	notEqual    map[int64]bool
	greaterThan int64
	lessThan    int64
	is32Bit     bool
	enabled     bool
}

func NewIntFilter(filters ...protocol.Filter) (*IntFilter, error) {
	return newIntFilter(false, filters...)
}

func NewInt32Filter(filters ...protocol.Filter) (*IntFilter, error) {
	return newIntFilter(true, filters...)
}

func newIntFilter(is32Bit bool, filters ...protocol.Filter) (*IntFilter, error) {
	filter := &IntFilter{
		equal:       map[int64]bool{},
		notEqual:    map[int64]bool{},
		greaterThan: maxIntVal,
		lessThan:    minIntVal,
		is32Bit:     is32Bit,
		enabled:     false,
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
	return f.greaterThan
}

func (f *IntFilter) Maximum() int64 {
	return f.lessThan
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *IntFilter) Filter(val int64) bool {
	result := !f.enabled || f.equal[val] || val > f.greaterThan || val < f.lessThan
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

func (f *IntFilter) addLesser(val int64) {
	if val > f.lessThan {
		f.lessThan = val
	}
}

func (f *IntFilter) addGreater(val int64) {
	if val < f.greaterThan {
		f.greaterThan = val
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
		f.addLesser(val)
	case Greater:
		f.addGreater(val)
	case LesserEqual:
		f.addEqual(val)
		f.addLesser(val)
	case GreaterEqual:
		f.addEqual(val)
		f.addGreater(val)
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
