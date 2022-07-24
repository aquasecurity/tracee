package filters

type BoolFilter struct {
	Value   bool
	enabled bool
}

func NewBoolFilter() *BoolFilter {
	return &BoolFilter{}
}

func (filter *BoolFilter) Parse(value string) error {
	filter.Enable()
	filter.Value = false
	if value[0] != '!' {
		filter.Value = true
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

func (filter *BoolFilter) FilterOut() bool {
	if filter.Value {
		return false
	} else {
		return true
	}
}
