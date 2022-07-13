package filters

import (
	"fmt"
	"math"
	"strconv"
	"sync"

	"github.com/aquasecurity/tracee/types/protocol"
)

const (
	minIntVal      = math.MinInt64
	minIntVal32Bit = math.MinInt32
	maxIntVal      = math.MaxInt64
	maxIntVal32Bit = math.MaxInt32
)

type IntFilter struct {
	is32Bit       bool
	equal         map[int64]bool
	notEqual      map[int64]bool
	maxLesser     int64
	leastGreatest int64
	enabled       bool
	mutex         sync.RWMutex
}

func NewIntFilter() *IntFilter {
	return newIntFilter(false)
}

func NewInt32Filter() *IntFilter {
	return newIntFilter(true)
}

// int filter implements a thread safe Filter for int64 values
func newIntFilter(is32Bit bool) *IntFilter {
	min := int64(minIntVal)
	max := int64(maxIntVal)

	if is32Bit {
		min = minIntVal32Bit
		max = maxIntVal32Bit
	}

	return &IntFilter{
		is32Bit:       is32Bit,
		equal:         make(map[int64]bool),
		notEqual:      make(map[int64]bool),
		maxLesser:     min,
		leastGreatest: max,
	}
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *IntFilter) Filter(val int64) bool {
	f.mutex.RLock()
	result := !f.enabled || f.equal[val] || val > f.leastGreatest || val < f.maxLesser
	if !result && f.notEqual[val] {
		f.mutex.RUnlock()
		return false
	}
	f.mutex.RUnlock()
	return result
}

func (f *IntFilter) validate(val int64) bool {
	if f.is32Bit {
		return val <= maxIntVal32Bit && val >= minIntVal32Bit
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
	if val > f.maxLesser {
		f.maxLesser = val
	}
}

func (f *IntFilter) addGreater(val int64) {
	if val < f.leastGreatest {
		f.leastGreatest = val
	}
}

func (f *IntFilter) add(val int64, operator Operator) error {
	if !f.validate(val) {
		return fmt.Errorf("filter value %d is unsupported", val)
	}
	switch operator {
	case Equal:
		f.mutex.Lock()
		f.addEqual(val)
		f.mutex.Unlock()
	case NotEqual:
		f.mutex.Lock()
		f.addNotEqual(val)
		f.mutex.Unlock()
	case Lesser:
		f.mutex.Lock()
		f.addLesser(val)
		f.mutex.Unlock()
	case Greater:
		f.mutex.Lock()
		f.addGreater(val)
		f.mutex.Unlock()
	case LesserEqual:
		f.mutex.Lock()
		f.addEqual(val)
		f.addLesser(val)
		f.mutex.Unlock()
	case GreaterEqual:
		f.mutex.Lock()
		f.addEqual(val)
		f.addGreater(val)
		f.mutex.Unlock()
	}
	return nil
}

func (f *IntFilter) Add(filterReq protocol.Filter) error {
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

func (f *IntFilter) Enable() {
	f.mutex.Lock()
	f.enabled = true
	f.mutex.Unlock()
}

func (f *IntFilter) Disable() {
	f.mutex.Lock()
	f.enabled = false
	f.mutex.Unlock()
}

func (f *IntFilter) Enabled() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.enabled
}

func (*IntFilter) Operators() []Operator {
	return []Operator{Equal, NotEqual, Greater, GreaterEqual, Lesser, LesserEqual}
}
