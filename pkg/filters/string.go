package filters

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/types/protocol"
)

//StringFilter implements a thread safe filter for string values
type StringFilter struct {
	equals     map[string]bool
	notEquals  map[string]bool
	prefixes   map[string]bool
	suffixes   map[string]bool
	contains   map[string]bool
	nePrefixes map[string]bool
	neSuffixes map[string]bool
	neContains map[string]bool
	enabled    bool
	mutex      sync.RWMutex
}

func NewStringFilter() *StringFilter {
	return &StringFilter{
		equals:     make(map[string]bool),
		notEquals:  make(map[string]bool),
		prefixes:   make(map[string]bool),
		suffixes:   make(map[string]bool),
		contains:   make(map[string]bool),
		neSuffixes: make(map[string]bool),
		nePrefixes: make(map[string]bool),
		neContains: make(map[string]bool),
	}
}

func (f *StringFilter) Filter(val string) bool {
	f.mutex.RLock()
	enabled := f.enabled
	equals := f.equals[val]
	notEquals := f.notEquals[val]
	suffixes := f.suffixes
	prefixes := f.prefixes
	contains := f.contains
	neSuffixes := f.neSuffixes
	nePrefixes := f.nePrefixes
	neContains := f.neContains
	notEqualsSet := len(f.notEquals) > 0 || len(neSuffixes) > 0 || len(nePrefixes) > 0
	f.mutex.RUnlock()
	if !enabled {
		return true
	}
	if equals {
		return true
	}
	for contain := range contains {
		if strings.Contains(val, contain) {
			return true
		}
	}
	for suffix := range suffixes {
		if strings.HasSuffix(val, suffix) {
			return true
		}
	}
	for prefix := range prefixes {
		if strings.HasPrefix(val, prefix) {
			return true
		}
	}
	if notEqualsSet {
		for contain := range neContains {
			if strings.Contains(val, contain) {
				return false
			}
		}
		for suffix := range neSuffixes {
			if strings.HasSuffix(val, suffix) {
				return false
			}
		}
		for prefix := range nePrefixes {
			if strings.HasPrefix(val, prefix) {
				return false
			}
		}
		res := !notEquals || equals
		return res
	}
	return false
}

func (f *StringFilter) Add(filterReq protocol.Filter) error {
	arr := filterReq.Value
	vals := make([]string, len(filterReq.Value))
	for i := 0; i < len(arr); i++ {
		val := arr[i]
		valStr, ok := val.(string)
		if !ok {
			return fmt.Errorf("failed to add to filter: invalid value: %s", val)
		}
		vals[i] = valStr
	}
	for _, val := range vals {
		err := f.add(val, Operator(filterReq.Operator))
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *StringFilter) add(val string, operator Operator) error {
	switch operator {
	case Equal:
		f.mutex.Lock()
		f.addEqual(val)
		f.mutex.Unlock()
	case NotEqual:
		f.mutex.Lock()
		f.addNotEqual(val)
		f.mutex.Unlock()
	default:
		return UnsupportedOperator(operator)
	}
	return nil
}

func (f *StringFilter) addEqual(val string) {
	prefixSet := val[len(val)-1] == '*'
	suffixSet := val[0] == '*'
	if prefixSet && suffixSet && len(val) > 1 {
		f.contains[val[1:len(val)-1]] = true
		return
	}
	if prefixSet {
		f.prefixes[val[:len(val)-1]] = true
		return
	}
	if suffixSet && len(val) > 1 {
		f.suffixes[val[1:]] = true
		return
	}
	if !prefixSet && !suffixSet {
		f.equals[val] = true
		return
	}
}

func (f *StringFilter) addNotEqual(val string) {
	prefixSet := val[len(val)-1] == '*'
	suffixSet := val[0] == '*'
	if prefixSet {
		f.nePrefixes[val[:len(val)-1]] = true
	}
	if suffixSet {
		f.neSuffixes[val[1:]] = true
	}
	if !prefixSet && !suffixSet {
		f.notEquals[val] = true
	}
}

func (f *StringFilter) Enable() {
	f.mutex.Lock()
	f.enabled = true
	f.mutex.Unlock()
}

func (f *StringFilter) Disable() {
	f.mutex.Lock()
	f.enabled = false
	f.mutex.Unlock()
}

func (f *StringFilter) Enabled() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.enabled
}

func (f *StringFilter) FilterOut() bool {
	if len(f.equals) > 0 && len(f.notEquals) == 0 {
		return false
	} else {
		return true
	}
}

// Next two functions basically exist to keep the old events to trace logic

// Equals returns all equality check values - direct, prefixed and suffixed
func (f *StringFilter) Equals() []string {
	res := []string{}
	for val := range f.equals {
		res = append(res, val)
	}
	for val := range f.prefixes {
		res = append(res, val)
	}
	for val := range f.suffixes {
		res = append(res, val)
	}
	return res
}

// NotEquals returns all non-equality check values - direct, prefixed and suffixed
func (f *StringFilter) NotEquals() []string {
	res := []string{}
	for val := range f.notEquals {
		res = append(res, val)
	}
	for val := range f.nePrefixes {
		res = append(res, val)
	}
	for val := range f.neSuffixes {
		res = append(res, val)
	}
	return res
}

func (*StringFilter) Operators() []Operator {
	return []Operator{Equal, NotEqual}
}

// MaxBpfStrFilterSize value should match MAX_STR_FILTER_SIZE defined in BPF code
const maxBPFStrFilterSize = 16

type BPFStringFilter struct {
	*StringFilter
}

func (f *BPFStringFilter) InitBpf(module *bpf.Module, mapName string) error {
	if !f.enabled {
		return nil
	}
	bpfMap, err := module.GetMap(mapName)
	if err != nil {
		return err
	}

	//Initialize the associated bpfMap
	//First initialize notEqual values since equality should take precedence
	for str := range f.notEquals {
		byteStr := make([]byte, maxBPFStrFilterSize)
		copy(byteStr, str)
		if err := bpfMap.Update(unsafe.Pointer(&byteStr[0]), unsafe.Pointer(&bpfFilterNotEqual)); err != nil {
			return err
		}
	}

	//Now - setup equality filters
	for str := range f.equals {
		byteStr := make([]byte, maxBPFStrFilterSize)
		copy(byteStr, str)
		if err := bpfMap.Update(unsafe.Pointer(&byteStr[0]), unsafe.Pointer(&bpfFilterEqual)); err != nil {
			return err
		}
	}

	return nil
}
