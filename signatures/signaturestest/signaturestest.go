package signaturestest

import (
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// FindingsHolder is a utility struct that defines types.SignatureHandler
// callback method and holds types.Finding values received as the callback's
// argument in memory.
type FindingsHolder struct {
	Values []types.Finding
}

func (h *FindingsHolder) OnFinding(f types.Finding) {
	h.Values = append(h.Values, f)
}

func (h *FindingsHolder) GroupBySigID() map[string]types.Finding {
	r := make(map[string]types.Finding)
	for _, v := range h.Values {
		r[v.SigMetadata.ID] = v
	}
	return r
}

func (h *FindingsHolder) FirstValue() *types.Finding {
	if len(h.Values) == 0 {
		return nil
	}
	return &h.Values[0]
}
