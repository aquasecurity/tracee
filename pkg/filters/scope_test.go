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
