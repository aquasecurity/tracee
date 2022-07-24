package filters

import (
	"fmt"
	"math"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/types/protocol"
)

const (
	minUIntVal uint64 = 0
	maxUIntVal uint64 = math.MaxUint64
)

type UIntFilter struct {
	equal       map[uint64]bool
	notEqual    map[uint64]bool
	greaterThan uint64
	lessThan    uint64
	is32Bit     bool
	enabled     bool
}

func NewUIntFilter(filters ...protocol.Filter) (*UIntFilter, error) {
	return newUIntFilter(false, filters...)
}

func NewUInt32Filter(filters ...protocol.Filter) (*UIntFilter, error) {
	return newUIntFilter(true, filters...)
}

func newUIntFilter(is32Bit bool, filters ...protocol.Filter) (*UIntFilter, error) {
	filter := &UIntFilter{
		equal:       map[uint64]bool{},
		notEqual:    map[uint64]bool{},
		greaterThan: maxUIntVal,
		lessThan:    minUIntVal,
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

// priority goes by (from most significant):
// 1. equality
// 2. greater
// 3. lesser
// 4. non equality
func (f *UIntFilter) Filter(val uint64) bool {
	result := !f.Enabled() || f.equal[val] || val > f.greaterThan || val < f.lessThan
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

func (f *UIntFilter) addLesser(val uint64) {
	if val > f.lessThan {
		f.lessThan = val
	}
}

func (f *UIntFilter) addGreater(val uint64) {
	if val < f.greaterThan {
		f.greaterThan = val
	}
}

func (f *UIntFilter) parse(filterReq protocol.Filter) error {
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

func (filter *UIntFilter) Enable() {
	filter.enabled = true
}

func (filter *UIntFilter) Disable() {
	filter.enabled = false
}

func (filter *UIntFilter) Enabled() bool {
	return filter.enabled
}

func (filter *UIntFilter) Minimum() uint64 {
	return filter.greaterThan
}

func (filter *UIntFilter) Maximum() uint64 {
	return filter.lessThan
}

type BPFUIntFilter struct {
	UIntFilter
	mapName string
}

func NewBPFUIntFilter(mapName string, filters ...protocol.Filter) (*BPFUIntFilter, error) {
	filter, err := NewUIntFilter(filters...)
	return &BPFUIntFilter{
		UIntFilter: *filter,
		mapName:    mapName,
	}, err
}

func NewBPFUInt32Filter(mapName string, filters ...protocol.Filter) (*BPFUIntFilter, error) {
	filter, err := NewUInt32Filter(filters...)
	return &BPFUIntFilter{
		UIntFilter: *filter,
		mapName:    mapName,
	}, err
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
	if len(filter.equal) > 0 && len(filter.notEqual) == 0 && filter.greaterThan == maxUIntVal && filter.lessThan == minUIntVal {
		return false
	} else {
		return true
	}
}
