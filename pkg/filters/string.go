package filters

import (
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/filters/sets"
)

type StringFilter struct {
	equal       map[string]bool
	notEqual    map[string]bool
	prefixes    sets.PrefixSet
	suffixes    sets.SuffixSet
	contains    map[string]bool
	notPrefixes sets.PrefixSet
	notSuffixes sets.SuffixSet
	notContains map[string]bool
	enabled     bool
}

func NewStringFilter() *StringFilter {
	return &StringFilter{
		equal:       map[string]bool{},
		notEqual:    map[string]bool{},
		prefixes:    sets.NewPrefixSet(),
		suffixes:    sets.NewSuffixSet(),
		notPrefixes: sets.NewPrefixSet(),
		notSuffixes: sets.NewSuffixSet(),
		contains:    map[string]bool{},
		notContains: map[string]bool{},
	}
}

// priority goes by (from most significant):
// 1. equality, suffixed, prefixed, contains
// 2. not equals, not suffixed, not prefixed, not contains
// This is done so if a conflicting "not" filter exists, we ignore it
func (f *StringFilter) Filter(val string) bool {
	enabled := f.enabled
	equals := f.equal[val]
	notEquals := f.notEqual[val]
	suffixes := f.suffixes
	prefixes := f.prefixes
	contains := f.contains
	notSuffixes := f.notSuffixes
	notPrefixes := f.notPrefixes
	notContains := f.notContains
	notEqualsSet := len(f.notEqual) > 0 || notSuffixes.Length() > 0 || notPrefixes.Length() > 0 || len(notContains) > 0
	if !enabled {
		return true
	}
	if equals {
		return true
	}
	if suffixes.Filter(val) {
		return true
	}
	if prefixes.Filter(val) {
		return true
	}
	for contain := range contains {
		if strings.Contains(val, contain) {
			return true
		}
	}
	if notEqualsSet {
		if notSuffixes.Filter(val) {
			return false
		}
		if notPrefixes.Filter(val) {
			return false
		}
		for contain := range notContains {
			if strings.Contains(val, contain) {
				return false
			}
		}
		res := !notEquals || equals
		return res
	}
	return false
}

func (f *StringFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return InvalidExpression(operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return InvalidExpression(operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for _, val := range values {
		err := f.add(val, stringToOperator(operatorString))
		if err != nil {
			return err
		}
	}

	f.Enable()

	return nil
}

func (f *StringFilter) add(val string, operator Operator) error {
	switch operator {
	case Equal:
		return f.addEqual(val)
	case NotEqual:
		return f.addNotEqual(val)
	default:
		return UnsupportedOperator(operator)
	}
}

func (f *StringFilter) addEqual(val string) error {
	if val == "*" || val == "**" {
		return InvalidValue(val)
	}
	prefixSet := val[len(val)-1] == '*'
	suffixSet := val[0] == '*'
	if prefixSet && suffixSet && len(val) > 1 {
		f.contains[val[1:len(val)-1]] = true
	} else if prefixSet {
		f.prefixes.Put(val[:len(val)-1])
	} else if suffixSet && len(val) > 1 {
		f.suffixes.Put(val[1:])
	} else if !prefixSet && !suffixSet {
		f.equal[val] = true
	}
	return nil
}

func (f *StringFilter) addNotEqual(val string) error {
	if val == "*" || val == "**" {
		return InvalidValue(val)
	}
	prefixSet := val[len(val)-1] == '*'
	suffixSet := val[0] == '*'
	if prefixSet && suffixSet && len(val) > 1 {
		f.notContains[val[1:len(val)-1]] = true
	} else if prefixSet {
		f.notPrefixes.Put(val[:len(val)-1])
	} else if suffixSet {
		f.notSuffixes.Put(val[1:])
	} else if !prefixSet && !suffixSet {
		f.notEqual[val] = true
	}
	return nil
}

func (f *StringFilter) Enable() {
	f.enabled = true
}

func (f *StringFilter) Disable() {
	f.enabled = false
}

func (f *StringFilter) Enabled() bool {
	return f.enabled
}

// Equals returns all equality check values - direct, prefixed and suffixed
func (f *StringFilter) Equal() []string {
	res := []string{}
	for val := range f.equal {
		res = append(res, val)
	}
	for val := range f.prefixes.Set {
		res = append(res, val)
	}
	for val := range f.suffixes.Set {
		res = append(res, val)
	}
	return res
}

// NotEquals returns all non-equality check values - direct, prefixed and suffixed
func (f *StringFilter) NotEqual() []string {
	res := []string{}
	for val := range f.notEqual {
		res = append(res, val)
	}
	for val := range f.notPrefixes.Set {
		res = append(res, val)
	}
	for val := range f.notSuffixes.Set {
		res = append(res, val)
	}
	return res
}

func (filter *StringFilter) FilterOut() bool {
	if len(filter.Equal()) > 0 && len(filter.NotEqual()) == 0 {
		return false
	} else {
		return true
	}
}

type BPFStringFilter struct {
	StringFilter
	mapName string
}

func NewBPFStringFilter(mapName string) *BPFStringFilter {
	return &BPFStringFilter{
		StringFilter: *NewStringFilter(),
		mapName:      mapName,
	}
}

func (filter *BPFStringFilter) InitBPF(bpfModule *bpf.Module) error {
	// MaxBpfStrFilterSize value should match MAX_STR_FILTER_SIZE defined in BPF code
	const maxBpfStrFilterSize = 16

	bpfFilterEqual := uint32(filterEqual) // const need local var for bpfMap.Update()
	bpfFilterNotEqual := uint32(filterNotEqual)

	if !filter.Enabled() {
		return nil
	}

	bpfMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return err
	}

	//Initialize the associated bpfMap
	//First initialize notEqual values since equality should take precedence
	for str := range filter.notEqual {
		byteStr := make([]byte, maxBpfStrFilterSize)
		copy(byteStr, str)
		if err := bpfMap.Update(unsafe.Pointer(&byteStr[0]), unsafe.Pointer(&bpfFilterNotEqual)); err != nil {
			return err
		}
	}

	//Now - setup equality filters
	for str := range filter.equal {
		byteStr := make([]byte, maxBpfStrFilterSize)
		copy(byteStr, str)
		if err := bpfMap.Update(unsafe.Pointer(&byteStr[0]), unsafe.Pointer(&bpfFilterEqual)); err != nil {
			return err
		}
	}

	return nil
}
