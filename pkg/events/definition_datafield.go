package events

import (
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/types/trace"
)

type DataField struct {
	trace.ArgMeta
	DecodeAs data.DecodeAs
}

// DataFieldsFromArgMeta converts a slice of trace.ArgMeta to
// a slice of DataField, with no defined DecodeAs type.
func DataFieldsFromArgMeta(argMeta []trace.ArgMeta) []DataField {
	dataFields := make([]DataField, 0, len(argMeta))
	for _, argMeta := range argMeta {
		dataFields = append(dataFields, DataField{
			ArgMeta: argMeta,
		})
	}
	return dataFields
}
