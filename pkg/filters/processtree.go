package filters

import (
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type ProcessTreeFilter struct {
	equal    map[uint32]struct{} // k=pid states that pid and its descendent should be traced
	notEqual map[uint32]struct{} // k=pid states that pid and its descendent should not be traced
	enabled  bool
}

// Compile-time check to ensure that ProcessTreeFilter implements the Cloner interface
var _ utils.Cloner[*ProcessTreeFilter] = &ProcessTreeFilter{}

func NewProcessTreeFilter() *ProcessTreeFilter {
	return &ProcessTreeFilter{
		equal:    map[uint32]struct{}{},
		notEqual: map[uint32]struct{}{},
		enabled:  false,
	}
}

func (f *ProcessTreeFilter) Enable() {
	f.enabled = true
}

func (f *ProcessTreeFilter) Disable() {
	f.enabled = false
}

func (f *ProcessTreeFilter) Enabled() bool {
	return f.enabled
}

func (f *ProcessTreeFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return InvalidExpression(operatorAndValues)
	}

	var (
		equalityOperator bool
		valuesString     string
	)

	if strings.HasPrefix(operatorAndValues, "=") {
		valuesString = operatorAndValues[1:]
		equalityOperator = true
	} else if strings.HasPrefix(operatorAndValues, "!=") {
		valuesString = operatorAndValues[2:]
		if len(valuesString) == 0 {
			return errfmt.Errorf("no value passed with operator in process tree filter")
		}
		equalityOperator = false
	} else {
		return InvalidExpression(operatorAndValues)
	}

	values := strings.Split(valuesString, ",")
	for _, value := range values {
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return errfmt.Errorf("invalid PID given to filter: %s", valuesString)
		}
		if equalityOperator {
			f.equal[uint32(pid)] = struct{}{}
		} else {
			f.notEqual[uint32(pid)] = struct{}{}
		}
	}

	f.Enable()

	return nil
}

func (f *ProcessTreeFilter) FilterOut() bool {
	if len(f.equal) > 0 && len(f.notEqual) == 0 {
		return false
	}

	return true
}

type ProcessTreeFilterEqualities struct {
	Equal    map[uint32]struct{}
	NotEqual map[uint32]struct{}
}

func (f *ProcessTreeFilter) Equalities() ProcessTreeFilterEqualities {
	if !f.Enabled() {
		return ProcessTreeFilterEqualities{
			Equal:    map[uint32]struct{}{},
			NotEqual: map[uint32]struct{}{},
		}
	}

	return ProcessTreeFilterEqualities{
		Equal:    maps.Clone(f.equal),
		NotEqual: maps.Clone(f.notEqual),
	}
}

func (f *ProcessTreeFilter) Clone() *ProcessTreeFilter {
	if f == nil {
		return nil
	}

	n := NewProcessTreeFilter()

	maps.Copy(n.equal, f.equal)
	maps.Copy(n.notEqual, f.notEqual)
	n.enabled = f.enabled

	return n
}
