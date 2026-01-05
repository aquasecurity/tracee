package derive

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

func Test_getFlagsFromEvent_NetworkFlags(t *testing.T) {
	tests := []struct {
		name          string
		event         *trace.Event
		expectedFlags int
	}{
		{
			name: "network flags argument present with int64 value",
			event: &trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "other", Type: "int"}, Value: int32(42)},
					{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int64"}, Value: int64(0x123)},
					{ArgMeta: trace.ArgMeta{Name: "payload", Type: "[]byte"}, Value: []byte{0x01, 0x02}},
				},
			},
			expectedFlags: 0x123,
		},
		{
			name: "network flags argument not present",
			event: &trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "other", Type: "int"}, Value: int32(42)},
					{ArgMeta: trace.ArgMeta{Name: "payload", Type: "[]byte"}, Value: []byte{0x01, 0x02}},
				},
			},
			expectedFlags: 0,
		},
		{
			name: "network flags argument present with wrong type",
			event: &trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "flags", Type: "string"}, Value: "not_a_number"},
				},
			},
			expectedFlags: 0,
		},
		{
			name: "empty arguments",
			event: &trace.Event{
				Args: []trace.Argument{},
			},
			expectedFlags: 0,
		},
		{
			name: "network packet with ingress direction flag",
			event: &trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int64"}, Value: int64(packetIngress)},
				},
			},
			expectedFlags: packetIngress,
		},
		{
			name: "network packet with egress direction flag",
			event: &trace.Event{
				Args: []trace.Argument{
					{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int64"}, Value: int64(packetEgress)},
				},
			},
			expectedFlags: packetEgress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFlagsFromEvent(tt.event)
			assert.Equal(t, tt.expectedFlags, result)
		})
	}
}
