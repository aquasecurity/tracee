package filters

import (
	"strings"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/filters/sets"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// ValueHandler is a function that can be passed to StringFilter to handle values when they are parsed
type ValueHandler func(string) (string, error)

type StringFilter struct {
	valueHandler ValueHandler
	equal        map[string]struct{}
	notEqual     map[string]struct{}
	prefixes     sets.PrefixSet
	suffixes     sets.SuffixSet
	contains     map[string]struct{}
	notPrefixes  sets.PrefixSet
	notSuffixes  sets.SuffixSet
	notContains  map[string]struct{}
	enabled      bool
}

// Compile-time check to ensure that StringFilter implements the Cloner interface
var _ utils.Cloner[*StringFilter] = &StringFilter{}

func NewStringFilter(valHandler ValueHandler) *StringFilter {
	return &StringFilter{
		valueHandler: valHandler,
		equal:        map[string]struct{}{},
		notEqual:     map[string]struct{}{},
		prefixes:     sets.NewPrefixSet(),
		suffixes:     sets.NewSuffixSet(),
		notPrefixes:  sets.NewPrefixSet(),
		notSuffixes:  sets.NewSuffixSet(),
		contains:     map[string]struct{}{},
		notContains:  map[string]struct{}{},
	}
}

func (f *StringFilter) Filter(val interface{}) bool {
	valStr, ok := val.(string)
	if !ok {
		return false
	}
	return f.filter(valStr)
}

// priority goes by (from most significant):
// 1. equality, suffixed, prefixed, contains
// 2. not equals, not suffixed, not prefixed, not contains
// This is done so if a conflicting "not" filter exists, we ignore it
func (f *StringFilter) filter(val string) bool {
	enabled := f.enabled
	_, equals := f.equal[val]
	_, notEquals := f.notEqual[val]
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

	var (
		val string
		err error
	)
	for _, val = range values {
		if f.valueHandler != nil {
			val, err = f.valueHandler(val)
			if err != nil {
				return errfmt.WrapError(err)
			}
		}

		err = f.add(val, stringToOperator(operatorString))
		if err != nil {
			return errfmt.WrapError(err)
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
		f.contains[val[1:len(val)-1]] = struct{}{}
	} else if prefixSet {
		f.prefixes.Put(val[:len(val)-1])
	} else if suffixSet && len(val) > 1 {
		f.suffixes.Put(val[1:])
	} else if !prefixSet && !suffixSet {
		f.equal[val] = struct{}{}
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
		f.notContains[val[1:len(val)-1]] = struct{}{}
	} else if prefixSet {
		f.notPrefixes.Put(val[:len(val)-1])
	} else if suffixSet {
		f.notSuffixes.Put(val[1:])
	} else if !prefixSet && !suffixSet {
		f.notEqual[val] = struct{}{}
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

func (f *StringFilter) FilterOut() bool {
	if len(f.Equal()) > 0 && len(f.NotEqual()) == 0 {
		return false
	}
	return true
}

type StringFilterEqualities struct {
	Equal    map[string]struct{}
	NotEqual map[string]struct{}
}

func (f *StringFilter) Equalities() StringFilterEqualities {
	if !f.Enabled() {
		return StringFilterEqualities{
			Equal:    map[string]struct{}{},
			NotEqual: map[string]struct{}{},
		}
	}

	return StringFilterEqualities{
		Equal:    maps.Clone(f.equal),
		NotEqual: maps.Clone(f.notEqual),
	}
}

func (f *StringFilter) Clone() *StringFilter {
	if f == nil {
		return nil
	}

	n := NewStringFilter(f.valueHandler)

	maps.Copy(n.equal, f.equal)
	maps.Copy(n.notEqual, f.notEqual)
	n.prefixes = *f.prefixes.Clone()
	n.suffixes = *f.suffixes.Clone()
	maps.Copy(n.contains, f.contains)
	n.notPrefixes = *f.notPrefixes.Clone()
	n.notSuffixes = *f.notSuffixes.Clone()
	maps.Copy(n.notContains, f.notContains)
	n.enabled = f.enabled

	return n
}
