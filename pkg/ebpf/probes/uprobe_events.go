package probes

type UprobeEvent interface {
	String() string
}

type UprobeEventSymbol string

func (e UprobeEventSymbol) String() string {
	return string(e)
}
