package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDataFilterProto_Disabled(t *testing.T) {
	t.Parallel()
	f := NewDataFilter()
	assert.True(t, f.FilterProto(nil))
	assert.True(t, f.FilterProto([]*v1beta1.EventValue{}))
}

func TestDataFilterProto_StringMatch(t *testing.T) {
	t.Parallel()

	f := NewDetectorDataFilter()
	require.NoError(t, f.Parse(events.SecurityFileOpen, "pathname", "=/etc/passwd"))

	// Match
	assert.True(t, f.FilterProto([]*v1beta1.EventValue{
		{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/etc/passwd"}},
	}))

	// No match
	assert.False(t, f.FilterProto([]*v1beta1.EventValue{
		{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/etc/shadow"}},
	}))

	// Field missing
	assert.False(t, f.FilterProto([]*v1beta1.EventValue{
		{Name: "other", Value: &v1beta1.EventValue_Str{Str: "/etc/passwd"}},
	}))

	// Empty slice
	assert.False(t, f.FilterProto([]*v1beta1.EventValue{}))
}

func TestDataFilterProto_IntMatch(t *testing.T) {
	t.Parallel()

	f := NewDetectorDataFilter()
	require.NoError(t, f.Parse(events.Read, "fd", "=3"))

	// Int32 match (fmt.Sprint(int32(3)) == "3")
	assert.True(t, f.FilterProto([]*v1beta1.EventValue{
		{Name: "fd", Value: &v1beta1.EventValue_Int32{Int32: 3}},
	}))

	// No match
	assert.False(t, f.FilterProto([]*v1beta1.EventValue{
		{Name: "fd", Value: &v1beta1.EventValue_Int32{Int32: 5}},
	}))
}

func TestDataFilterProto_MultipleFields(t *testing.T) {
	t.Parallel()

	f := NewDetectorDataFilter()
	require.NoError(t, f.Parse(events.SecurityFileOpen, "pathname", "=/etc/passwd"))

	data := []*v1beta1.EventValue{
		{Name: "flags", Value: &v1beta1.EventValue_Int32{Int32: 0}},
		{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/etc/passwd"}},
		{Name: "dev", Value: &v1beta1.EventValue_UInt32{UInt32: 123}},
	}
	assert.True(t, f.FilterProto(data))
}

func TestDataFilterProto_SkipsReturnValue(t *testing.T) {
	t.Parallel()

	f := NewDetectorDataFilter()
	require.NoError(t, f.Parse(events.Read, "fd", "=3"))

	data := []*v1beta1.EventValue{
		{Name: "returnValue", Value: &v1beta1.EventValue_Int64{Int64: -1}},
		{Name: "fd", Value: &v1beta1.EventValue_Int32{Int32: 3}},
	}

	assert.True(t, f.FilterProto(data))

	traceEvt := events.ConvertFromProto(&v1beta1.Event{Data: data})
	assert.True(t, f.Filter(traceEvt.Args))
	assert.Equal(t, f.Filter(traceEvt.Args), f.FilterProto(data))
}

func TestDataFilterProto_Int32ArrayMatch(t *testing.T) {
	t.Parallel()

	f := NewDetectorDataFilter()
	require.NoError(t, f.parseFilter("argv", "=[1 2 3]", func() Filter[*StringFilter] {
		return NewStringFilter(nil)
	}))
	f.Enable()

	data := []*v1beta1.EventValue{
		{Name: "argv", Value: &v1beta1.EventValue_Int32Array{
			Int32Array: &v1beta1.Int32Array{Value: []int32{1, 2, 3}},
		}},
	}
	assert.True(t, f.FilterProto(data))

	traceEvt := events.ConvertFromProto(&v1beta1.Event{Data: data})
	assert.Equal(t, f.Filter(traceEvt.Args), f.FilterProto(data))
}

func TestProtoValueToInterface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ev       *v1beta1.EventValue
		expected interface{}
	}{
		{"int32", &v1beta1.EventValue{Value: &v1beta1.EventValue_Int32{Int32: 42}}, int32(42)},
		{"int64", &v1beta1.EventValue{Value: &v1beta1.EventValue_Int64{Int64: 99}}, int64(99)},
		{"uint32", &v1beta1.EventValue{Value: &v1beta1.EventValue_UInt32{UInt32: 7}}, uint32(7)},
		{"uint64", &v1beta1.EventValue{Value: &v1beta1.EventValue_UInt64{UInt64: 8}}, uint64(8)},
		{"str", &v1beta1.EventValue{Value: &v1beta1.EventValue_Str{Str: "hello"}}, "hello"},
		{"bool", &v1beta1.EventValue{Value: &v1beta1.EventValue_Bool{Bool: true}}, true},
		{"pointer", &v1beta1.EventValue{Value: &v1beta1.EventValue_Pointer{Pointer: 0xdead}}, trace.Pointer(0xdead)},
		{"int32_array", &v1beta1.EventValue{Value: &v1beta1.EventValue_Int32Array{
			Int32Array: &v1beta1.Int32Array{Value: []int32{1, 2, 3}},
		}}, []int32{1, 2, 3}},
		{"bytes", &v1beta1.EventValue{Value: &v1beta1.EventValue_Bytes{Bytes: []byte("abc")}}, []byte("abc")},
		{"str_array", &v1beta1.EventValue{Value: &v1beta1.EventValue_StrArray{
			StrArray: &v1beta1.StringArray{Value: []string{"a", "b"}},
		}}, []string{"a", "b"}},
		{"str_array_nil", &v1beta1.EventValue{Value: &v1beta1.EventValue_StrArray{
			StrArray: nil,
		}}, nil},
		// nil oneof falls through to default, which returns the EventValue itself
		// (matches convertDataToArgs behavior for unknown types)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := protoValueToInterface(tt.ev)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Separate test for nil value case — returns the EventValue itself
	t.Run("nil_value_returns_ev", func(t *testing.T) {
		t.Parallel()
		ev := &v1beta1.EventValue{}
		result := protoValueToInterface(ev)
		assert.Equal(t, ev, result)
	})
}
