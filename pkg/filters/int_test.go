package filters

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntFilterParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		expressions []string
		vals        []int64
		expected    []bool
	}{
		{
			name: "simple equality checks",
			expressions: []string{
				"=50,-2,8",
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{true, true, true, false, false},
		},
		{
			name: "conflict - same equal and non equal",
			expressions: []string{
				"=50,8",
				"!=50",
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{true, false, true, false, false},
		},
		{
			name: "excluding greater and lower, with equals in between",
			expressions: []string{
				">50",
				"<-2",
				"=8",
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{false, false, true, true, true},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filter := NewIntFilter()
			for _, expr := range tc.expressions {
				err := filter.Parse(expr)
				require.NoError(t, err)
			}
			result := make([]bool, len(tc.vals))
			for i, val := range tc.vals {
				result[i] = filter.Filter(val)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIntFilterClone(t *testing.T) {
	t.Parallel()

	filter64 := NewIntFilter()
	err := filter64.Parse("=50,8")
	require.NoError(t, err)

	copy64 := filter64.Clone().(*IntFilter[int64])

	if !reflect.DeepEqual(filter64, copy64) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	err = copy64.Parse("=51")
	require.NoError(t, err)
	if reflect.DeepEqual(filter64, copy64) {
		t.Errorf("Changes to copied filter affected the original")
	}

	filter32 := NewInt32Filter()
	err = filter32.Parse("=50,8")
	require.NoError(t, err)

	copy32 := filter32.Clone().(*IntFilter[int32])

	if !reflect.DeepEqual(filter32, copy32) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	err = copy32.Parse("=51")
	require.NoError(t, err)
	if reflect.DeepEqual(filter32, copy32) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
