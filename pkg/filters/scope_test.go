package filters

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters/sets"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestScopeFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewScopeFilter()
	err := filter.Parse("processorId", "=0")
	require.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		ScopeFilter{},
		NumericFilter[int64]{},
		NumericFilter[uint64]{},
		BoolFilter{},
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
	)
	if !cmp.Equal(filter, copy, opt1) {
		diff := cmp.Diff(filter, copy, opt1)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse("pid", "=1")
	require.NoError(t, err)
	if cmp.Equal(filter, copy, opt1) {
		t.Error("Changes to copied filter affected the original")
	}
}

func TestScopeFilter_ContainerStarted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		field          string
		operatorValues string
		event          trace.Event
		expectedMatch  bool
		expectedErrStr string
	}{
		{
			name:           "container - matches any container",
			field:          "container",
			operatorValues: "",
			event: trace.Event{
				Container:    trace.Container{ID: "abc123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expectedMatch: true,
		},
		{
			name:           "container - matches started container",
			field:          "container",
			operatorValues: "",
			event: trace.Event{
				Container:    trace.Container{ID: "abc123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: true},
			},
			expectedMatch: true,
		},
		{
			name:           "container - does not match host",
			field:          "container",
			operatorValues: "",
			event: trace.Event{
				Container:    trace.Container{ID: ""},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expectedMatch: false,
		},
		{
			name:           "container=started - matches started container",
			field:          "container",
			operatorValues: "=started",
			event: trace.Event{
				Container:    trace.Container{ID: "abc123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: true},
			},
			expectedMatch: true,
		},
		{
			name:           "container=started - does not match init container",
			field:          "container",
			operatorValues: "=started",
			event: trace.Event{
				Container:    trace.Container{ID: "abc123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expectedMatch: false,
		},
		{
			name:           "container=started - does not match host",
			field:          "container",
			operatorValues: "=started",
			event: trace.Event{
				Container:    trace.Container{ID: ""},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expectedMatch: false,
		},
		{
			name:           "host - matches host events",
			field:          "host",
			operatorValues: "",
			event: trace.Event{
				Container:    trace.Container{ID: ""},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expectedMatch: true,
		},
		{
			name:           "host - does not match container",
			field:          "host",
			operatorValues: "",
			event: trace.Event{
				Container:    trace.Container{ID: "abc123"},
				ContextFlags: trace.ContextFlags{ContainerStarted: false},
			},
			expectedMatch: false,
		},
		{
			name:           "container=invalid - returns error",
			field:          "container",
			operatorValues: "=invalid",
			event:          trace.Event{},
			expectedMatch:  false,
			expectedErrStr: "invalid filter expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filter := NewScopeFilter()
			err := filter.Parse(tt.field, tt.operatorValues)

			if tt.expectedErrStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrStr)
				return
			}

			require.NoError(t, err)
			match := filter.Filter(tt.event)
			assert.Equal(t, tt.expectedMatch, match, "Event should match=%v, got=%v", tt.expectedMatch, match)
		})
	}
}

// TestScopeFilter_ContainerPodFiltersWithInequality tests that container/pod filters
// with inequality operators (!=) do not implicitly exclude host events.
// This is a regression test for https://github.com/aquasecurity/tracee/issues/5224
func TestScopeFilter_ContainerPodFiltersWithInequality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		field          string
		operatorValues string
		event          trace.Event
		expectedMatch  bool
	}{
		// podNamespace tests
		{
			name:           "podNamespace!= - matches host events",
			field:          "podNamespace",
			operatorValues: "!=kube-system",
			event: trace.Event{
				Container:  trace.Container{ID: ""},
				Kubernetes: trace.Kubernetes{PodNamespace: ""},
			},
			expectedMatch: true,
		},
		{
			name:           "podNamespace!= - excludes matching pod",
			field:          "podNamespace",
			operatorValues: "!=kube-system",
			event: trace.Event{
				Container:  trace.Container{ID: "abc123"},
				Kubernetes: trace.Kubernetes{PodNamespace: "kube-system"},
			},
			expectedMatch: false,
		},
		{
			name:           "podNamespace!= - matches non-matching pod",
			field:          "podNamespace",
			operatorValues: "!=kube-system",
			event: trace.Event{
				Container:  trace.Container{ID: "abc123"},
				Kubernetes: trace.Kubernetes{PodNamespace: "default"},
			},
			expectedMatch: true,
		},
		{
			name:           "podNamespace= - excludes host events",
			field:          "podNamespace",
			operatorValues: "=default",
			event: trace.Event{
				Container:  trace.Container{ID: ""},
				Kubernetes: trace.Kubernetes{PodNamespace: ""},
			},
			expectedMatch: false,
		},
		{
			name:           "podNamespace= - matches matching pod",
			field:          "podNamespace",
			operatorValues: "=default",
			event: trace.Event{
				Container:  trace.Container{ID: "abc123"},
				Kubernetes: trace.Kubernetes{PodNamespace: "default"},
			},
			expectedMatch: true,
		},
		// podName tests
		{
			name:           "podName!= - matches host events",
			field:          "podName",
			operatorValues: "!=some-pod",
			event: trace.Event{
				Container:  trace.Container{ID: ""},
				Kubernetes: trace.Kubernetes{PodName: ""},
			},
			expectedMatch: true,
		},
		{
			name:           "podName!= - excludes matching pod",
			field:          "podName",
			operatorValues: "!=some-pod",
			event: trace.Event{
				Container:  trace.Container{ID: "abc123"},
				Kubernetes: trace.Kubernetes{PodName: "some-pod"},
			},
			expectedMatch: false,
		},
		// containerImage tests
		{
			name:           "containerImage!= - matches host events",
			field:          "containerImage",
			operatorValues: "!=nginx",
			event: trace.Event{
				Container: trace.Container{ID: "", ImageName: ""},
			},
			expectedMatch: true,
		},
		{
			name:           "containerImage!= - excludes matching container",
			field:          "containerImage",
			operatorValues: "!=nginx",
			event: trace.Event{
				Container: trace.Container{ID: "abc123", ImageName: "nginx"},
			},
			expectedMatch: false,
		},
		{
			name:           "containerImage!= - matches non-matching container",
			field:          "containerImage",
			operatorValues: "!=nginx",
			event: trace.Event{
				Container: trace.Container{ID: "abc123", ImageName: "redis"},
			},
			expectedMatch: true,
		},
		{
			name:           "containerImage= - excludes host events",
			field:          "containerImage",
			operatorValues: "=nginx",
			event: trace.Event{
				Container: trace.Container{ID: "", ImageName: ""},
			},
			expectedMatch: false,
		},
		// containerId tests
		{
			name:           "containerId!= - matches host events",
			field:          "containerId",
			operatorValues: "!=abc123",
			event: trace.Event{
				Container: trace.Container{ID: ""},
			},
			expectedMatch: true,
		},
		{
			name:           "containerId!= - excludes matching container",
			field:          "containerId",
			operatorValues: "!=abc123",
			event: trace.Event{
				Container: trace.Container{ID: "abc123"},
			},
			expectedMatch: false,
		},
		// containerName tests
		{
			name:           "containerName!= - matches host events",
			field:          "containerName",
			operatorValues: "!=my-container",
			event: trace.Event{
				Container: trace.Container{ID: "", Name: ""},
			},
			expectedMatch: true,
		},
		{
			name:           "containerName= - excludes host events",
			field:          "containerName",
			operatorValues: "=my-container",
			event: trace.Event{
				Container: trace.Container{ID: "", Name: ""},
			},
			expectedMatch: false,
		},
		// podUid tests
		{
			name:           "podUid!= - matches host events",
			field:          "podUid",
			operatorValues: "!=12345",
			event: trace.Event{
				Container:  trace.Container{ID: ""},
				Kubernetes: trace.Kubernetes{PodUID: ""},
			},
			expectedMatch: true,
		},
		{
			name:           "podUid= - excludes host events",
			field:          "podUid",
			operatorValues: "=12345",
			event: trace.Event{
				Container:  trace.Container{ID: "", Name: ""},
				Kubernetes: trace.Kubernetes{PodUID: ""},
			},
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filter := NewScopeFilter()
			err := filter.Parse(tt.field, tt.operatorValues)
			require.NoError(t, err)

			match := filter.Filter(tt.event)
			assert.Equal(t, tt.expectedMatch, match, "Event should match=%v, got=%v", tt.expectedMatch, match)
		})
	}
}
