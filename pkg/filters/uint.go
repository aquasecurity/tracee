package filters

import (
	"fmt"
	"math"
	"strconv"
	"sync"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/types/protocol"
)

const (
	minUIntVal      = 0
	maxUIntVal      = math.MaxUint64
	maxUIntVal32Bit = math.MaxUint32
)

type UIntFilter struct {
	is32Bit        bool
	equal          map[uint64]bool
	notEqual       map[uint64]bool
	maxLessThan    uint64
	minGreaterThan uint64
	enabled        bool
	mutex          sync.RWMutex
}

func NewUIntFilter() *UIntFilter {
	return newUIntFilter(false)
}

func NewUInt32Filter() *UIntFilter {
	return newUIntFilter(true)
}

// int filter implements a thread safe Filter for uint64 values
func newUIntFilter(is32Bit bool) *UIntFilter {
	min := uint64(0)
	max := uint64(maxUIntVal)

	return &UIntFilter{
		is32Bit:        is32Bit,
		equal:          make(map[uint64]bool),
		notEqual:       make(map[uint64]bool),
		maxLessThan:    min,
		minGreaterThan: max,
	}
}

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *UIntFilter) Filter(val uint64) bool {
	f.mutex.RLock()
	result := !f.enabled || f.equal[val] || val > f.minGreaterThan || val < f.maxLessThan
	if !result && f.notEqual[val] {
		f.mutex.RUnlock()
		return false
	}
	f.mutex.RUnlock()
	return result
}

func (f *UIntFilter) validate(val uint64) bool {
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

func (f *UIntFilter) addLesser(val uint64) {
	if val > f.maxLessThan {
		f.maxLessThan = val
	}
}

func (f *UIntFilter) addGreater(val uint64) {
	if val < f.minGreaterThan {
		f.minGreaterThan = val
	}
}

func (f *UIntFilter) Add(filterReq protocol.Filter) error {
	for _, val := range filterReq.Value {
		val := fmt.Sprintf("%v", val)
		valUint, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to add to filter: invalid value: %v", val)
		}
		err = f.add(valUint, Operator(filterReq.Operator))
		if err != nil {
			return fmt.Errorf("failed to build filter: %s", err)
		}
	}
	return nil
}

func (f *UIntFilter) add(val uint64, operator Operator) error {
	if !f.validate(val) {
		return fmt.Errorf("failed to add filter: filter value %d is unsupported", val)
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

func (f *UIntFilter) Enable() {
	f.mutex.Lock()
	f.enabled = true
	f.mutex.Unlock()
}

func (f *UIntFilter) Disable() {
	f.mutex.Lock()
	f.enabled = false
	f.mutex.Unlock()
}

func (f *UIntFilter) Enabled() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.enabled
}

func (f *UIntFilter) FilterOut() bool {
	if len(f.equal) > 0 && len(f.notEqual) == 0 && f.minGreaterThan == maxUIntVal && f.maxLessThan == minUIntVal {
		return false
	} else {
		return true
	}
}

func (f *UIntFilter) Minimum() uint64 {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.minGreaterThan
}

func (f *UIntFilter) Maximum() uint64 {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.maxLessThan
}

func (*UIntFilter) Operators() []Operator {
	return []Operator{Equal, NotEqual, Greater, GreaterEqual, Lesser, LesserEqual}
}

type BPFUintFilter struct {
	*UIntFilter
}

func (f *BPFUintFilter) InitBpf(module *bpf.Module, equalityMap string) error {
	if !f.enabled {
		return nil
	}
	var err error

	equalityFilterMap, err := module.GetMap(equalityMap) //map for equality/non-equality filters
	if err != nil {
		return err
	}

	for equalFilter := range f.equal {
		if f.is32Bit {
			equalU32 := uint32(equalFilter)
			err = equalityFilterMap.Update(unsafe.Pointer(&equalU32), unsafe.Pointer(&bpfFilterEqual))
		} else {
			err = equalityFilterMap.Update(unsafe.Pointer(&equalFilter), unsafe.Pointer(&bpfFilterEqual))
		}
		if err != nil {
			return err
		}
	}
	for notEqualFilter := range f.notEqual {
		if f.is32Bit {
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
