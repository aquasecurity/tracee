package filters

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/protocol"
)

type Operator uint

const (
	Equal Operator = iota
	NotEqual
	Lesser
	LesserEqual
	Greater
	GreaterEqual
)

func (o Operator) String() string {
	switch o {
	case Equal:
		return "=="
	case NotEqual:
		return "!="
	case Greater:
		return ">"
	case Lesser:
		return "<"
	case GreaterEqual:
		return ">="
	case LesserEqual:
		return "<="
	}
	return ""
}

// This is a generic represantation which cannot be implemented
// With generics this may be a viable interface, with T replacing interface{}
// Filters can be enabled or disabled - if a filter is enabled it will be skipped
type Filter interface {
	// Filter(val interface{}) bool
	parse(req protocol.Filter) error
	Enable()
	Disable()
	Enabled() bool
	Operators() []Operator
}

func UnsupportedOperator(op Operator) error {
	return fmt.Errorf("failed to add filter: unsupported operator %s", op.String())
}

const (
	filterNotEqual uint32 = iota
	filterEqual
)
