package filters

import (
	"strconv"
	"strings"
)

type BoolFilter struct {
	trueEnabled  bool
	falseEnabled bool
	enabled      bool
}

func NewBoolFilter() *BoolFilter {
	return &BoolFilter{}
}

func (filter *BoolFilter) Filter(val interface{}) bool {
	filterable, ok := val.(bool)
	if !ok {
		return false
	}
	return filter.filter(filterable)
}

func (filter *BoolFilter) filter(val bool) bool {
	if !filter.Enabled() {
		return true
	}
	trueEnabled := filter.trueEnabled
	falseEnabled := filter.falseEnabled
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

// BoolFilter can support the following expressions
// values in <> are ignored
// field -> field=true
// !field -> field=false
// field=true
// field=false
// field!=true
// field!=false
func (filter *BoolFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 1 {
		return InvalidExpression(operatorAndValues)
	}

	filter.Enable()

	// case of =bools...
	if operatorAndValues[0] == '=' {
		valuesString := operatorAndValues[1:]
		vals := strings.Split(valuesString, ",")
		for _, val := range vals {
			boolVal, err := strconv.ParseBool(val)
			if err != nil {
				return InvalidValue(val)
			}
			if err = filter.add(boolVal, Equal); err != nil {
				return err
			}
		}
		return nil
	}

	// case of !=bools...
	if operatorAndValues[0] == '!' && operatorAndValues[1] == '=' {
		if len(operatorAndValues) < 2+len("true") {
			return InvalidExpression(operatorAndValues)
		}
		valuesString := operatorAndValues[2:]
		vals := strings.Split(valuesString, ",")
		for _, val := range vals {
			boolVal, err := strconv.ParseBool(val)
			if err != nil {
				return InvalidValue(val)
			}
			if err = filter.add(boolVal, NotEqual); err != nil {
				return err
			}
		}
		return nil
	}

	// case of !field
	if operatorAndValues[0] == '!' {
		filter.falseEnabled = true
		return nil
	}

	// final case just field
	filter.trueEnabled = true

	return nil
}

func (filter *BoolFilter) add(val bool, operator Operator) error {
	switch operator {
	case Equal:
		if val {
			filter.trueEnabled = true
		} else {
			filter.falseEnabled = true
		}
	case NotEqual:
		if val {
			filter.falseEnabled = true
		} else {
			filter.trueEnabled = true
		}
	default:
		return UnsupportedOperator(operator)
	}
	return nil
}

func (f *BoolFilter) Enable() {
	f.enabled = true
}

func (f *BoolFilter) Disable() {
	f.enabled = false
}

func (f *BoolFilter) Enabled() bool {
	return f.enabled
}

func (filter *BoolFilter) Value() bool {
	return filter.trueEnabled
}

func (filter *BoolFilter) FilterOut() bool {
	if filter.Value() {
		return false
	} else {
		return true
	}
}
