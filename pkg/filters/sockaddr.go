package filters

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/tracee/types/trace"
)

type sockAddrFilterValue struct {
	Port    int    `json:"port"`
	Address string `json:"address"`
	Family  string `json:"family"`
}

type SockAddrFilter struct {
	equal    map[sockAddrFilterValue]bool
	notEqual map[sockAddrFilterValue]bool
	enabled  bool
}

func NewSockAddrFilter() *SockAddrFilter {
	return &SockAddrFilter{
		equal:    map[sockAddrFilterValue]bool{},
		notEqual: map[sockAddrFilterValue]bool{},
	}
}

func (f *SockAddrFilter) Filter(val interface{}) bool {
	filterable, ok := val.(trace.SockAddr)
	if !ok {
		return false
	}
	return f.filter(filterable)
}

func (f *SockAddrFilter) filter(val trace.SockAddr) bool {
	if !f.enabled {
		return true
	}
	for equal := range f.equal {
		if compareSockAddr(val, equal) {
			return true
		}
	}
	for notEqual := range f.notEqual {
		if compareSockAddr(val, notEqual) {
			return false
		}
	}
	return f.FilterOut()
}

func compareSockAddr(compared trace.SockAddr, fixed sockAddrFilterValue) bool {
	return (fixed.Family == "" || compared.Family() == fixed.Family) &&
		(fixed.Address == "" || compared.Address() == fixed.Address) &&
		(fixed.Port == 0 || compared.Port() == fixed.Port)

}

func (f *SockAddrFilter) Parse(operatorAndValues string) error {
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

	values := strings.Split(valuesString, "},")

	for i, val := range values {
		if i != len(values)-1 {
			val += "}"
		}
		unmarshaled := sockAddrFilterValue{}
		json.Unmarshal([]byte(val), &unmarshaled)
		err := f.add(unmarshaled, stringToOperator(operatorString))
		if err != nil {
			return err
		}
	}

	f.Enable()

	return nil
}

func (f *SockAddrFilter) add(val sockAddrFilterValue, operator Operator) error {
	switch operator {
	case Equal:
		return f.addEqual(val)
	case NotEqual:
		return f.addNotEqual(val)
	default:
		return UnsupportedOperator(operator)
	}
}

func (f *SockAddrFilter) addEqual(val sockAddrFilterValue) error {
	f.equal[val] = true
	return nil
}

func (f *SockAddrFilter) addNotEqual(val sockAddrFilterValue) error {
	f.notEqual[val] = true
	return nil
}

func (f *SockAddrFilter) Enable() {
	f.enabled = true
}

func (f *SockAddrFilter) Disable() {
	f.enabled = false
}

func (f *SockAddrFilter) Enabled() bool {
	return f.enabled
}

func (filter *SockAddrFilter) FilterOut() bool {
	return !(len(filter.equal) > 0 && len(filter.notEqual) == 0)
}
