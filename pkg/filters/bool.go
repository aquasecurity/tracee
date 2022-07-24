package filters

type BoolFilter struct {
	Value   bool
	Enabled bool
}

func NewBoolFilter() *BoolFilter {
	return &BoolFilter{}
}

func (filter *BoolFilter) Parse(value string) error {
	filter.Enabled = true
	filter.Value = false
	if value[0] != '!' {
		filter.Value = true
	}

	return nil
}

func (filter *BoolFilter) FilterOut() bool {
	if filter.Value {
		return false
	} else {
		return true
	}
}
