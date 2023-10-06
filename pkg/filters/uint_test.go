package filters

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUIntFilterParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		expressions []string
		vals        []uint64
		expected    []bool
	}{
		{
			name: "simple equality checks",
			expressions: []string{
				"=50,7,8",
			},
			vals:     []uint64{50, 149, 7, 8},
			expected: []bool{true, false, true, true},
		},
		{
			name: "conflict - same equal and non equal",
			expressions: []string{
				"=50,8",
				"!=50",
			},
			vals:     []uint64{50, 149, 7, 8},
			expected: []bool{true, false, false, true},
		},
		{
			name: "excluding greater and lower, with equals in between",
			expressions: []string{
				">50,51",
				"<4",
				"=8",
			},
			vals:     []uint64{50, 4, 8, 2, 51, 52},
			expected: []bool{false, false, true, true, true, true},
		},
		{
			name: "lower/equal than",
			expressions: []string{
				"<=6",
			},
			vals:     []uint64{6, 5, 4, 7},
			expected: []bool{true, true, true, false},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filter := NewUIntFilter()
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

func TestUIntFilterClone(t *testing.T) {
	t.Parallel()

	filter64 := NewUIntFilter()
	err := filter64.Parse("=50,8")
	require.NoError(t, err)

	copy64 := filter64.Clone().(*UIntFilter[uint64])

	if !reflect.DeepEqual(filter64, copy64) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	copy64.Parse("=51")
	if reflect.DeepEqual(filter64, copy64) {
		t.Errorf("Changes to copied filter affected the original")
	}

	filter32 := NewUInt32Filter()
	err = filter32.Parse("=50,8")
	require.NoError(t, err)

	copy32 := filter32.Clone().(*UIntFilter[uint32])

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
