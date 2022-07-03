package detect

import (
	"fmt"
	"reflect"
	"strings"
)

type FilterOperator int

const (
	Equal FilterOperator = iota
	NotEqual
	Lower
	LowerEqual
	Greater
	GreaterEqual
)

func (o FilterOperator) String() string {
	switch o {
	case Equal:
		return "="
	case NotEqual:
		return "!="
	case Greater:
		return ">"
	case Lower:
		return "<"
	case GreaterEqual:
		return ">="
	case LowerEqual:
		return "<="
	}
	return ""
}

func (o FilterOperator) not() FilterOperator {
	switch o {
	case Equal:
		return NotEqual
	case NotEqual:
		return Equal
	case Greater:
		return LowerEqual
	case Lower:
		return GreaterEqual
	case GreaterEqual:
		return Lower
	case LowerEqual:
		return Greater
	}
	// sanity
	return -1
}

type Filter struct {
	Field    string
	Operator FilterOperator
	Value    []interface{}
}

// Not returns a "mirrored" filter with a negated operator
func (f Filter) Not() Filter {
	return Filter{f.Field, f.Operator.not(), f.Value}
}

func (f Filter) String() string {
	stringVals := make([]string, len(f.Value))
	for i := range f.Value {
		stringVals[i] = fmt.Sprint(f.Value[i])
	}
	return f.Field + f.Operator.String() + strings.Join(stringVals, ",")
}

//
// filter building helpers
//

func EqualFilter(field string, vals ...interface{}) Filter {
	return Filter{field, Equal, flattenIfaceArr(vals)}
}

func NotEqualFilter(field string, vals ...interface{}) Filter {
	return Filter{field, NotEqual, flattenIfaceArr(vals)}
}

func LowerFilter(field string, vals ...interface{}) Filter {
	return Filter{field, Lower, flattenIfaceArr(vals)}
}

func LowerEqFilter(field string, vals ...interface{}) Filter {
	return Filter{field, LowerEqual, flattenIfaceArr(vals)}
}

func GreaterFilter(field string, vals ...interface{}) Filter {
	return Filter{field, Greater, flattenIfaceArr(vals)}
}

func GreaterEqFilter(field string, vals ...interface{}) Filter {
	return Filter{field, GreaterEqual, flattenIfaceArr(vals)}
}

//
// string filter helpers
//

// PrefixFilter returns an EqualFilter with values representing prefixes
func PrefixFilter(field string, prefixes ...string) Filter {
	prefixVals := []interface{}{}
	for _, prefix := range prefixes {
		prefixVals = append(prefixVals, prefix+"*")
	}
	return EqualFilter(field, prefixVals...)
}

// SuffixFilter returns an EqualFilter with values representing suffixes
func SuffixFilter(field string, suffixes ...string) Filter {
	suffixVals := []interface{}{}
	for _, suffix := range suffixes {
		suffixVals = append(suffixVals, "*"+suffix)
	}
	return EqualFilter(field, suffixVals...)
}

// ContainsFilter returns an EqualFilter with values representing contained values
func ContainsFilter(field string, contains ...string) Filter {
	containedVals := []interface{}{}
	for _, contained := range contains {
		containedVals = append(containedVals, "*"+contained+"*")
	}
	return EqualFilter(field, containedVals...)
}

// flattenIfaceArr flattens an array of interface{} values
// this is needed because we would like to pass []string values to the helpers
func flattenIfaceArr(vals []interface{}) []interface{} {
	res := make([]interface{}, 0)
	for _, val := range vals {
		if isSlice(val) {
			sliceVal := reflect.ValueOf(val)
			for i := 0; i < sliceVal.Len(); i++ {
				res = append(res, sliceVal.Index(i).Interface())
			}
		} else {
			res = append(res, val)
		}
	}
	return res
}

func isSlice(v interface{}) bool {
	kind := reflect.TypeOf(v).Kind()
	return kind == reflect.Slice || kind == reflect.Array
}
