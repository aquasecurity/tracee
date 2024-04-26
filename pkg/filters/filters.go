package filters

type Operator uint

const (
	Equal Operator = iota
	NotEqual
	Lower
	LowerEqual
	Greater
	GreaterEqual
)

func (o Operator) String() string {
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

func stringToOperator(op string) Operator {
	switch op {
	case "=":
		return Equal
	case "!=":
		return NotEqual
	case ">":
		return Greater
	case "<":
		return Lower
	case ">=":
		return GreaterEqual
	case "<=":
		return LowerEqual
	}
	return Equal
}

// This is a generic representation which cannot be implemented
// With generics this may be a viable interface, with U replacing interface{}
// Filters can be enabled or disabled - if a filter is enabled it will be skipped
type Filter[T any] interface {
	Clone() T

	Filter(val interface{}) bool
	Parse(operatorAndValues string) error
	Enable()
	Disable()
	Enabled() bool
}

const (
	filterNotEqual uint32 = iota
	filterEqual
)
