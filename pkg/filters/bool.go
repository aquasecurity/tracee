package filters

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/tracee/types/protocol"
)

type BoolFilter struct {
	trueEnabled  bool
	falseEnabled bool
	enabled      bool
}

func NewBoolFilter(filters ...protocol.Filter) (*BoolFilter, error) {
	filter := &BoolFilter{}

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

func (filter *BoolFilter) Filter(val bool) bool {
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

func (filter *BoolFilter) Value() bool {
	return filter.trueEnabled
}

func (filter *BoolFilter) parse(filterReq protocol.Filter) error {
	for _, val := range filterReq.Value {
		val := fmt.Sprintf("%v", val)
		valBool, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("failed to add to filter: invalid value: %v", val)
		}
		err = filter.add(valBool, Operator(filterReq.Operator))
		if err != nil {
			return fmt.Errorf("failed to build filter: %s", err)
		}
	}
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

func (filter *BoolFilter) Enable() {
	filter.enabled = true
}

func (filter *BoolFilter) Disable() {
	filter.enabled = false
}

func (filter *BoolFilter) Enabled() bool {
	return filter.enabled
}

func (filter *BoolFilter) FilterOut() bool {
	// if only false is enabled we filter out, otherwise filter in
	if !filter.trueEnabled && filter.falseEnabled {
		return true
	}
	return false
}
