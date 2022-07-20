package filters

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/aquasecurity/tracee/types/protocol"
)

type BoolFilter struct {
	trueEnabled  bool
	falseEnabled bool
	enabled      bool
	mutex        sync.RWMutex
}

// BoolFilter is a thread safe Filter for boolean values
func NewBoolFilter() *BoolFilter {
	return &BoolFilter{}
}

func (f *BoolFilter) Filter(val bool) bool {
	if !f.enabled {
		return true
	}
	f.mutex.RLock()
	trueEnabled := f.trueEnabled
	falseEnabled := f.falseEnabled
	f.mutex.RUnlock()
	if trueEnabled && falseEnabled {
		return true
	}
	if trueEnabled && !falseEnabled {
		return val
	}
	if !trueEnabled && falseEnabled {
		return !val
	}
	return false //last case is !trueEnabled && !falseEnabled which means no filter was added
}

func (f *BoolFilter) Value() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.trueEnabled
}

func (f *BoolFilter) Add(filterReq protocol.Filter) error {
	for _, val := range filterReq.Value {
		val := fmt.Sprintf("%v", val)
		valBool, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("failed to add to filter: invalid value: %v", val)
		}
		err = f.add(valBool, Operator(filterReq.Operator))
		if err != nil {
			return fmt.Errorf("failed to build filter: %s", err)
		}
	}
	return nil
}

func (f *BoolFilter) add(val bool, operator Operator) error {
	switch operator {
	case Equal:
		if val {
			f.mutex.Lock()
			f.trueEnabled = true
			f.mutex.Unlock()
		} else {
			f.mutex.Lock()
			f.falseEnabled = true
			f.mutex.Unlock()
		}
	case NotEqual:
		if val {
			f.mutex.Lock()
			f.falseEnabled = true
			f.mutex.Unlock()
		} else {
			f.mutex.Lock()
			f.trueEnabled = true
			f.mutex.Unlock()
		}
	default:
		return UnsupportedOperator(operator)
	}
	return nil
}

func (f *BoolFilter) Enable() {
	f.mutex.Lock()
	f.enabled = true
	f.mutex.Unlock()
}

func (f *BoolFilter) Disable() {
	f.mutex.Lock()
	f.enabled = false
	f.mutex.Unlock()
}

func (f *BoolFilter) Enabled() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.enabled
}

func (f *BoolFilter) FilterOut() bool {
	// if only one is enabled then we filter values that are non-true or non-false, which means filtering out
	if f.trueEnabled && !f.falseEnabled {
		return false
	}
	if !f.trueEnabled && f.falseEnabled {
		return true
	}
	return false
}

func (*BoolFilter) Operators() []Operator {
	return []Operator{Equal, NotEqual}
}
