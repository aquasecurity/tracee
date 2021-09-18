package regosig

import (
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type index map[types.SignatureEventSelector]map[string]struct{}

func newIndex(sigIDToSelectedEvents map[string][]types.SignatureEventSelector) index {
	idx := make(map[types.SignatureEventSelector]map[string]struct{})
	for sigID, selectedEvents := range sigIDToSelectedEvents {
		for _, es := range selectedEvents {
			if es.Name == "" {
				es.Name = "*"
			}
			if _, ok := idx[es]; !ok {
				idx[es] = make(map[string]struct{})
			}
			idx[es][sigID] = struct{}{}
		}
	}
	return idx
}

func (idx index) hasAnySignatureMatchingEventName(ee types.Event) bool {
	signatures, ok := idx[types.SignatureEventSelector{Source: "tracee", Name: ee.(external.Event).EventName}]
	return ok && len(signatures) > 0
}

func (idx index) hasAnySignatureMatchingAnyEventName() bool {
	signatures, ok := idx[types.SignatureEventSelector{Source: "tracee", Name: "*"}]
	return ok && len(signatures) > 0
}

func (idx index) getSignaturesMatchingEvent(ee types.Event) []string {
	var r []string
	signatures, ok := idx[types.SignatureEventSelector{Source: "tracee", Name: ee.(external.Event).EventName}]
	if ok {
		for s, _ := range signatures {
			r = append(r, s)
		}
	}
	signatures, ok = idx[types.SignatureEventSelector{Source: "tracee", Name: "*"}]
	if ok {
		for s, _ := range signatures {
			r = append(r, s)
		}
	}
	return r
}
