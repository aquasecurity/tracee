package filters

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/utils"
)

type BoolFilter struct {
	trueEnabled  bool
	falseEnabled bool
	enabled      bool
}

// Compile-time check to ensure that BoolFilter implements the Cloner interface
var _ utils.Cloner[*BoolFilter] = &BoolFilter{}

func NewBoolFilter() *BoolFilter {
	return &BoolFilter{}
}

func (f *BoolFilter) Filter(val interface{}) bool {
	filterable, ok := val.(bool)
	if !ok {
		return false
	}
	return f.filter(filterable)
}

func (f *BoolFilter) filter(val bool) bool {
	if !f.Enabled() {
		return true
	}
	trueEnabled := f.trueEnabled
	falseEnabled := f.falseEnabled
	if trueEnabled && falseEnabled {
		return true
	}
	if trueEnabled && !falseEnabled {
		return val
	}
	if !trueEnabled && falseEnabled {
		return !val
	}
	return false // last case is !trueEnabled && !falseEnabled which means no filter was added
}

// BoolFilter can support the following expressions
// values in <> are ignored
// field -> field=true
// not-field -> field=false
// field=true
// field=false
// field!=true
// field!=false
func (f *BoolFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 1 {
		return InvalidExpression(operatorAndValues)
	}

	f.Enable()

	// case of =bools...
	if operatorAndValues[0] == '=' {
		valuesString := operatorAndValues[1:]
		vals := strings.Split(valuesString, ",")
		for _, val := range vals {
			boolVal, err := strconv.ParseBool(val)
			if err != nil {
				return InvalidValue(val)
			}
			if err = f.add(boolVal, Equal); err != nil {
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
			if err = f.add(boolVal, NotEqual); err != nil {
				return err
			}
		}
		return nil
	}

	// case of not-field
	if strings.HasPrefix(operatorAndValues, "not-") {
		f.falseEnabled = true
		return nil
	}

	// final case just field
	f.trueEnabled = true

	return nil
}

func (f *BoolFilter) add(val bool, operator Operator) error {
	switch operator {
	case Equal:
		if val {
			f.trueEnabled = true
		} else {
			f.falseEnabled = true
		}
	case NotEqual:
		if val {
			f.falseEnabled = true
		} else {
			f.trueEnabled = true
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

func (f *BoolFilter) Value() bool {
	return f.trueEnabled
}

func (f *BoolFilter) FilterOut() bool {
	return !f.Value()
}

func (f *BoolFilter) Clone() *BoolFilter {
	if f == nil {
		return nil
	}

	return &BoolFilter{
		trueEnabled:  f.trueEnabled,
		falseEnabled: f.falseEnabled,
		enabled:      f.enabled,
	}
}
