package filters

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	minIntVal int64 = math.MinInt64
	maxIntVal int64 = math.MaxInt64
)

type IntFilter struct {
	Equal       []int64
	NotEqual    []int64
	GreaterThan int64
	LessThan    int64
	Is32Bit     bool
	enabled     bool
}

func NewIntFilter() *IntFilter {
	return newIntFilter(false)
}

func NewInt32Filter() *IntFilter {
	return newIntFilter(true)
}

func newIntFilter(is32Bit bool) *IntFilter {
	return &IntFilter{
		Equal:       []int64{},
		NotEqual:    []int64{},
		GreaterThan: maxIntVal,
		LessThan:    minIntVal,
		Is32Bit:     is32Bit,
		enabled:     false,
	}
}

func (f *IntFilter) Enable() {
	f.enabled = true
}

func (f *IntFilter) Disable() {
	f.enabled = false
}

func (f *IntFilter) Enabled() bool {
	return f.enabled
}

func (f *IntFilter) Minimum() int64 {
	return f.GreaterThan
}

func (f *IntFilter) Maximum() int64 {
	return f.LessThan
}

func (filter *IntFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		val, err := strconv.ParseInt(values[i], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid filter value: %s", values[i])
		}
		if filter.Is32Bit && (val > math.MaxInt32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, val)
		case "!=":
			filter.NotEqual = append(filter.NotEqual, val)
		case ">":
			if (filter.GreaterThan == maxIntVal) || (val > filter.GreaterThan) {
				filter.GreaterThan = val
			}
		case "<":
			if (filter.LessThan == minIntVal) || (val < filter.LessThan) {
				filter.LessThan = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	filter.Enable()

	return nil
}
