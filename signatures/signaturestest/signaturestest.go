package signaturestest

import "github.com/aquasecurity/tracee/types/detect"

// FindingsHolder is a utility struct that defines detect.SignatureHandler
// callback method and holds detect.Finding values received as the callback's
// argument in memory.
type FindingsHolder struct {
	Values []*detect.Finding
}

func (h *FindingsHolder) OnFinding(f *detect.Finding) {
	h.Values = append(h.Values, f)
}

func (h *FindingsHolder) GroupBySigID() map[string]*detect.Finding {
	r := make(map[string]*detect.Finding)
	for _, v := range h.Values {
		r[v.SigMetadata.ID] = v
	}
	return r
}

func (h *FindingsHolder) FirstValue() *detect.Finding {
	if len(h.Values) == 0 {
		return nil
	}
	return h.Values[0]
}
