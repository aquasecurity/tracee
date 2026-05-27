package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
)

// assertScopeFilterParity checks FilterProto matches Filter(ConvertFromProto(e)).
func assertScopeFilterParity(t *testing.T, f *ScopeFilter, e *v1beta1.Event) {
	t.Helper()
	traceEvt := events.ConvertFromProto(e)
	want := f.Filter(*traceEvt)
	got := f.FilterProto(e)
	assert.Equal(t, want, got, "FilterProto must match Filter(ConvertFromProto)")
}

func TestScopeFilterProto_ParityWithConvertFromProto(t *testing.T) {
	t.Parallel()

	fullEvent := &v1beta1.Event{
		Timestamp: timestamppb.Now(),
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid:     &wrapperspb.UInt32Value{Value: 42},
				HostPid: &wrapperspb.UInt32Value{Value: 100},
				RealUser: &v1beta1.User{
					Id: &wrapperspb.UInt32Value{Value: 1000},
				},
				Thread: &v1beta1.Thread{
					Name:    "myproc",
					Syscall: "read",
					Tid:     &wrapperspb.UInt32Value{Value: 43},
					HostTid: &wrapperspb.UInt32Value{Value: 101},
				},
				Ancestors: []*v1beta1.Process{
					{
						Pid:     &wrapperspb.UInt32Value{Value: 10},
						HostPid: &wrapperspb.UInt32Value{Value: 50},
					},
				},
			},
			Container: &v1beta1.Container{Id: "c1", Started: true},
			K8S: &v1beta1.K8S{
				Pod:       &v1beta1.Pod{Name: "mypod", Uid: "pod-uid-1"},
				Namespace: &v1beta1.K8SNamespace{Name: "default"},
			},
		},
	}

	hostEvent := &v1beta1.Event{
		Workload: &v1beta1.Workload{},
	}

	type filterSpec struct {
		field string
		op    string
	}

	cases := []struct {
		name    string
		filters []filterSpec
		event   *v1beta1.Event
	}{
		{
			name:    "disabled filter",
			filters: nil,
			event:   fullEvent,
		},
		{
			name:    "container",
			filters: []filterSpec{{field: "container"}},
			event:   fullEvent,
		},
		{
			name:    "container started",
			filters: []filterSpec{{field: "container", op: "=started"}},
			event:   fullEvent,
		},
		{
			name:    "host",
			filters: []filterSpec{{field: "host"}},
			event:   hostEvent,
		},
		{
			name: "pid and comm",
			filters: []filterSpec{
				{field: "pid", op: "=42"},
				{field: "comm", op: "=myproc"},
			},
			event: fullEvent,
		},
		{
			name: "ppid from ancestor",
			filters: []filterSpec{
				{field: "ppid", op: "=10"},
			},
			event: fullEvent,
		},
		{
			name: "k8s and container id",
			filters: []filterSpec{
				{field: "podName", op: "=mypod"},
				{field: "containerId", op: "=c1"},
			},
			event: fullEvent,
		},
		{
			name:    "nil workload",
			filters: []filterSpec{{field: "pid", op: "=1"}},
			event:   &v1beta1.Event{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := NewScopeFilter()
			for _, spec := range tc.filters {
				require.NoError(t, f.Parse(spec.field, spec.op))
			}
			assertScopeFilterParity(t, f, tc.event)
		})
	}
}

func assertDataFilterParity(t *testing.T, f *DataFilter, data []*v1beta1.EventValue) {
	t.Helper()
	traceEvt := events.ConvertFromProto(&v1beta1.Event{Data: data})
	want := f.Filter(traceEvt.Args)
	got := f.FilterProto(data)
	assert.Equal(t, want, got, "FilterProto must match Filter(ConvertFromProto).Args")
}

func TestDataFilterProto_ParityWithConvertFromProto(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		eventID   events.ID
		field     string
		expr      string
		data      []*v1beta1.EventValue
		setupFunc func(*DataFilter) error // when set, bypasses event field validation
	}{
		{
			name:    "pathname string",
			eventID: events.SecurityFileOpen,
			field:   "pathname",
			expr:    "=/etc/passwd",
			data: []*v1beta1.EventValue{
				{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/etc/passwd"}},
			},
		},
		{
			name:    "int32 fd",
			eventID: events.Read,
			field:   "fd",
			expr:    "=3",
			data: []*v1beta1.EventValue{
				{Name: "fd", Value: &v1beta1.EventValue_Int32{Int32: 3}},
			},
		},
		{
			name: "pointer",
			data: []*v1beta1.EventValue{
				{Name: "buf", Value: &v1beta1.EventValue_Pointer{Pointer: 0xdead}},
			},
			setupFunc: func(f *DataFilter) error {
				return f.parseFilter("buf", "=57005", func() Filter[*StringFilter] {
					return NewStringFilter(nil)
				})
			},
		},
		{
			name: "int32 array",
			data: []*v1beta1.EventValue{
				{Name: "argv", Value: &v1beta1.EventValue_Int32Array{
					Int32Array: &v1beta1.Int32Array{Value: []int32{1, 2, 3}},
				}},
			},
			setupFunc: func(f *DataFilter) error {
				return f.parseFilter("argv", "=[1 2 3]", func() Filter[*StringFilter] {
					return NewStringFilter(nil)
				})
			},
		},
		{
			name: "bytes",
			data: []*v1beta1.EventValue{
				{Name: "data", Value: &v1beta1.EventValue_Bytes{Bytes: []byte("abc")}},
			},
			setupFunc: func(f *DataFilter) error {
				return f.parseFilter("data", "=[97 98 99]", func() Filter[*StringFilter] {
					return NewStringFilter(nil)
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := NewDetectorDataFilter()
			var err error
			if tc.setupFunc != nil {
				err = tc.setupFunc(f)
			} else {
				err = f.Parse(tc.eventID, tc.field, tc.expr)
			}
			require.NoError(t, err)
			f.Enable()
			assertDataFilterParity(t, f, tc.data)
		})
	}
}

func TestScopeFilterProto_ParityHostPpidFromAncestor(t *testing.T) {
	t.Parallel()

	f := NewScopeFilter()
	require.NoError(t, f.hostPpidFilter.Parse("=50"))
	f.hostPpidFilter.Enable()
	f.Enable()

	e := &v1beta1.Event{
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Ancestors: []*v1beta1.Process{
					{HostPid: &wrapperspb.UInt32Value{Value: 50}},
				},
			},
		},
	}
	assertScopeFilterParity(t, f, e)
}
