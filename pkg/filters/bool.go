package filters

type BoolFilter struct {
	Value   bool
	Enabled bool
}

func (filter *BoolFilter) Parse(value string) error {
	filter.Enabled = true
	filter.Value = false
	if value[0] != '!' {
		filter.Value = true
	}

	return nil
}

func (filter *BoolFilter) DefaultFilter() bool {
	if filter.Value {
		return false
	} else {
		return true
	}
}
