package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

func TestScopeFilterProto_Disabled(t *testing.T) {
	t.Parallel()
	f := NewScopeFilter()
	// Disabled filter passes everything
	assert.True(t, f.FilterProto(nil))
	assert.True(t, f.FilterProto(&v1beta1.Event{}))
}

func TestScopeFilterProto_NilSafety(t *testing.T) {
	t.Parallel()

	f := NewScopeFilter()
	require.NoError(t, f.Parse("pid", "=1"))

	// Nil workload
	assert.False(t, f.FilterProto(&v1beta1.Event{}))

	// Nil process
	assert.False(t, f.FilterProto(&v1beta1.Event{
		Workload: &v1beta1.Workload{},
	}))

	// Nil pid wrapper
	assert.False(t, f.FilterProto(&v1beta1.Event{
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{},
		},
	}))
}

func TestScopeFilterProto_Container(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		field         string
		operatorValue string
		event         *v1beta1.Event
		expected      bool
	}{
		{
			name:  "container - matches container event",
			field: "container",
			event: &v1beta1.Event{
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{Id: "abc123"},
				},
			},
			expected: true,
		},
		{
			name:  "container - rejects host event (no container)",
			field: "container",
			event: &v1beta1.Event{
				Workload: &v1beta1.Workload{},
			},
			expected: false,
		},
		{
			name:     "container - rejects nil workload",
			field:    "container",
			event:    &v1beta1.Event{},
			expected: false,
		},
		{
			name:          "container=started - matches started",
			field:         "container",
			operatorValue: "=started",
			event: &v1beta1.Event{
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{Id: "abc", Started: true},
				},
			},
			expected: true,
		},
		{
			name:          "container=started - rejects not started",
			field:         "container",
			operatorValue: "=started",
			event: &v1beta1.Event{
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{Id: "abc", Started: false},
				},
			},
			expected: false,
		},
		{
			name:  "host - matches host event",
			field: "host",
			event: &v1beta1.Event{
				Workload: &v1beta1.Workload{},
			},
			expected: true,
		},
		{
			name:  "host - rejects container event",
			field: "host",
			event: &v1beta1.Event{
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{Id: "abc123"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := NewScopeFilter()
			require.NoError(t, f.Parse(tt.field, tt.operatorValue))
			assert.Equal(t, tt.expected, f.FilterProto(tt.event))
		})
	}
}

func TestScopeFilterProto_ProcessFields(t *testing.T) {
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
			Container: &v1beta1.Container{Id: "c1"},
			K8S: &v1beta1.K8S{
				Pod:       &v1beta1.Pod{Name: "mypod", Uid: "pod-uid-1"},
				Namespace: &v1beta1.K8SNamespace{Name: "default"},
			},
		},
	}

	tests := []struct {
		name          string
		field         string
		operatorValue string
		expected      bool
	}{
		{"pid match", "pid", "=42", true},
		{"pid no match", "pid", "=99", false},
		{"hostPid match", "hostPid", "=100", true},
		{"hostPid no match", "hostPid", "=999", false},
		{"tid match", "tid", "=43", true},
		{"hostTid match", "hostTid", "=101", true},
		{"uid match", "uid", "=1000", true},
		{"uid no match", "uid", "=0", false},
		{"ppid match", "ppid", "=10", true},
		{"ppid no match", "ppid", "=99", false},
		{"processName match", "comm", "=myproc", true},
		{"processName no match", "comm", "=other", false},
		{"syscall match", "syscall", "=read", true},
		{"syscall no match", "syscall", "=write", false},
		{"podName match", "podName", "=mypod", true},
		{"podName no match", "podName", "=other", false},
		{"podNamespace match", "podNamespace", "=default", true},
		{"podUid match", "podUid", "=pod-uid-1", true},
		{"containerId match", "containerId", "=c1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := NewScopeFilter()
			require.NoError(t, f.Parse(tt.field, tt.operatorValue))
			assert.Equal(t, tt.expected, f.FilterProto(fullEvent),
				"field=%s op=%s", tt.field, tt.operatorValue)
		})
	}
}

func TestScopeFilterProto_MultipleFilters(t *testing.T) {
	t.Parallel()

	f := NewScopeFilter()
	require.NoError(t, f.Parse("container", ""))
	require.NoError(t, f.Parse("pid", "=42"))

	// Both match
	assert.True(t, f.FilterProto(&v1beta1.Event{
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{Id: "c1"},
			Process: &v1beta1.Process{
				Pid: &wrapperspb.UInt32Value{Value: 42},
			},
		},
	}))

	// Container matches, pid doesn't
	assert.False(t, f.FilterProto(&v1beta1.Event{
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{Id: "c1"},
			Process: &v1beta1.Process{
				Pid: &wrapperspb.UInt32Value{Value: 99},
			},
		},
	}))

	// Pid matches, not a container
	assert.False(t, f.FilterProto(&v1beta1.Event{
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: &wrapperspb.UInt32Value{Value: 42},
			},
		},
	}))
}
