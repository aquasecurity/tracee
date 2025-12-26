package filters

import (
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNumericFilterParse tests parsing for both signed and unsigned types
func TestNumericFilterParse(t *testing.T) {
	t.Parallel()

	t.Run("Int64", func(t *testing.T) {
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
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
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
	})

	t.Run("UInt64", func(t *testing.T) {
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
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
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
	})
}

// TestNumericFilterClone tests cloning for all numeric types
func TestNumericFilterClone(t *testing.T) {
	t.Parallel()

	t.Run("Int64 Clone", func(t *testing.T) {
		testCloneLogic(t, NewIntFilter(), NumericFilter[int64]{})
	})

	t.Run("Int32 Clone", func(t *testing.T) {
		testCloneLogic(t, NewInt32Filter(), NumericFilter[int32]{})
	})

	t.Run("UInt64 Clone", func(t *testing.T) {
		testCloneLogic(t, NewUIntFilter(), NumericFilter[uint64]{})
	})

	t.Run("UInt32 Clone", func(t *testing.T) {
		testCloneLogic(t, NewUInt32Filter(), NumericFilter[uint32]{})
	})
}

// Generic clone test logic
func testCloneLogic[T NumericConstraint](t *testing.T, filter *NumericFilter[T], typeForComparison any) {
	err := filter.Parse("=50,8")
	require.NoError(t, err)

	cloned := filter.Clone()

	opt := cmp.AllowUnexported(typeForComparison)
	if !cmp.Equal(filter, cloned, opt) {
		diff := cmp.Diff(filter, cloned, opt)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// Ensure changes to copy don't affect original
	err = cloned.Parse("=51")
	require.NoError(t, err)
	if cmp.Equal(filter, cloned, opt) {
		t.Error("Changes to copied filter affected the original")
	}
}

func TestNumericFilterNewMethods(t *testing.T) {
	t.Parallel()

	// Test NewNumericFilter directly
	t.Run("NewNumericFilter", func(t *testing.T) {
		filter := NewNumericFilter[int64]()
		assert.NotNil(t, filter)
		assert.False(t, filter.Enabled())
		assert.Equal(t, GetUnsetMin[int64](), filter.Minimum())
		assert.Equal(t, GetUnsetMax[int64](), filter.Maximum())
	})

	// Test helper functions
	t.Run("Helper functions", func(t *testing.T) {
		// Test GetUnsetMin/GetUnsetMax for all supported numeric types

		// 32-bit types
		assert.Equal(t, uint32(math.MaxUint32), GetUnsetMin[uint32]())
		assert.Equal(t, uint32(0), GetUnsetMax[uint32]())
		assert.Equal(t, int32(math.MaxInt32), GetUnsetMin[int32]())
		assert.Equal(t, int32(math.MinInt32), GetUnsetMax[int32]())

		// 64-bit types
		assert.Equal(t, uint64(math.MaxUint64), GetUnsetMin[uint64]())
		assert.Equal(t, uint64(0), GetUnsetMax[uint64]())
		assert.Equal(t, int64(math.MaxInt64), GetUnsetMin[int64]())
		assert.Equal(t, int64(math.MinInt64), GetUnsetMax[int64]())
	})
}

func TestNumericFilterMethods(t *testing.T) {
	t.Parallel()

	// Test Equalities method
	t.Run("Equalities", func(t *testing.T) {
		filter := NewUIntFilter()
		err := filter.Parse("=42,100")
		require.NoError(t, err)

		eqs := filter.Equalities()
		assert.Len(t, eqs.Equal, 2)
		assert.Contains(t, eqs.Equal, uint64(42))
		assert.Contains(t, eqs.Equal, uint64(100))
		assert.Empty(t, eqs.NotEqual)

		// Test disabled filter
		filter.Disable()
		eqsDisabled := filter.Equalities()
		assert.Empty(t, eqsDisabled.Equal)
		assert.Empty(t, eqsDisabled.NotEqual)
	})

	// Test type-safe Minimum and Maximum methods
	t.Run("Minimum and Maximum", func(t *testing.T) {
		filter := NewUIntFilter()

		// Test unset values
		assert.Equal(t, GetUnsetMin[uint64](), filter.Minimum())
		assert.Equal(t, GetUnsetMax[uint64](), filter.Maximum())

		// Test with range
		err := filter.Parse(">10")
		require.NoError(t, err)
		assert.Equal(t, uint64(10), filter.Minimum())
		assert.Equal(t, GetUnsetMax[uint64](), filter.Maximum())

		filter2 := NewUIntFilter()
		err = filter2.Parse("<100")
		require.NoError(t, err)
		assert.Equal(t, GetUnsetMin[uint64](), filter2.Minimum())
		assert.Equal(t, uint64(100), filter2.Maximum())
	})

	// Test Equalities method for signed types
	t.Run("Equalities for signed types", func(t *testing.T) {
		filter := NewIntFilter()
		err := filter.Parse("=-5,10")
		require.NoError(t, err)

		eqs := filter.Equalities()
		assert.Len(t, eqs.Equal, 2)
		assert.Contains(t, eqs.Equal, int64(-5))
		assert.Contains(t, eqs.Equal, int64(10))
		assert.Empty(t, eqs.NotEqual)

		// Test disabled filter
		filter.Disable()
		eqsDisabled := filter.Equalities()
		assert.Empty(t, eqsDisabled.Equal)
		assert.Empty(t, eqsDisabled.NotEqual)
	})
}

func TestNumericFilterEnableDisable(t *testing.T) {
	t.Parallel()

	filter := NewIntFilter()
	assert.False(t, filter.Enabled())

	filter.Enable()
	assert.True(t, filter.Enabled())

	filter.Disable()
	assert.False(t, filter.Enabled())
}

func TestNumericFilterInMinMaxRange(t *testing.T) {
	t.Parallel()

	// Test with no range set
	t.Run("no range set", func(t *testing.T) {
		filter := NewUIntFilter()
		assert.True(t, filter.InMinMaxRange(uint64(42)))
		assert.True(t, filter.InMinMaxRange(uint64(0)))
		assert.True(t, filter.InMinMaxRange(uint64(1000)))
	})

	// Test with min only
	t.Run("min only", func(t *testing.T) {
		filter := NewUIntFilter()
		err := filter.Parse(">10")
		require.NoError(t, err)

		assert.False(t, filter.InMinMaxRange(uint64(5)))
		assert.False(t, filter.InMinMaxRange(uint64(10)))
		assert.True(t, filter.InMinMaxRange(uint64(15)))
	})

	// Test with max only
	t.Run("max only", func(t *testing.T) {
		filter := NewUIntFilter()
		err := filter.Parse("<100")
		require.NoError(t, err)

		assert.True(t, filter.InMinMaxRange(uint64(50)))
		assert.False(t, filter.InMinMaxRange(uint64(100)))
		assert.False(t, filter.InMinMaxRange(uint64(150)))
	})

	// Test with both min and max
	t.Run("min and max", func(t *testing.T) {
		filter := NewUIntFilter()
		err := filter.Parse(">10")
		require.NoError(t, err)
		err = filter.Parse("<100")
		require.NoError(t, err)

		assert.False(t, filter.InMinMaxRange(uint64(5)))
		assert.False(t, filter.InMinMaxRange(uint64(10)))
		assert.True(t, filter.InMinMaxRange(uint64(50)))
		assert.False(t, filter.InMinMaxRange(uint64(100)))
		assert.False(t, filter.InMinMaxRange(uint64(150)))
	})
}

func TestNumericFilterMatchIfKeyMissing(t *testing.T) {
	t.Parallel()

	// Test with only equal values
	t.Run("only equal values", func(t *testing.T) {
		filter := NewIntFilter()
		err := filter.Parse("=42,100")
		require.NoError(t, err)

		assert.False(t, filter.MatchIfKeyMissing())
	})

	// Test with not equal values
	t.Run("with not equal values", func(t *testing.T) {
		filter := NewIntFilter()
		err := filter.Parse("!=42")
		require.NoError(t, err)

		assert.True(t, filter.MatchIfKeyMissing())
	})

	// Test with range values
	t.Run("with range values", func(t *testing.T) {
		filter := NewIntFilter()
		err := filter.Parse(">10")
		require.NoError(t, err)

		assert.True(t, filter.MatchIfKeyMissing())
	})

	// Test with mixed equal and not equal
	t.Run("mixed equal and not equal", func(t *testing.T) {
		filter := NewIntFilter()
		err := filter.Parse("=42")
		require.NoError(t, err)
		err = filter.Parse("!=100")
		require.NoError(t, err)

		assert.True(t, filter.MatchIfKeyMissing())
	})
}

func TestNumericFilterValidation(t *testing.T) {
	t.Parallel()

	// Test 32-bit unsigned validation
	t.Run("uint32 validation", func(t *testing.T) {
		filter := NewUInt32Filter()

		// Valid values
		err := filter.Parse("=42")
		assert.NoError(t, err)

		err = filter.Parse("=4294967295") // MaxUint32
		assert.NoError(t, err)

		// Invalid value (too large for uint32)
		err = filter.Parse("=4294967296") // MaxUint32 + 1
		assert.Error(t, err)
	})

	// Test 32-bit signed validation
	t.Run("int32 validation", func(t *testing.T) {
		filter := NewInt32Filter()

		// Valid values
		err := filter.Parse("=42")
		assert.NoError(t, err)

		err = filter.Parse("=-2147483648") // MinInt32
		assert.NoError(t, err)

		err = filter.Parse("=2147483647") // MaxInt32
		assert.NoError(t, err)

		// Invalid values
		err = filter.Parse("=-2147483649") // MinInt32 - 1
		assert.Error(t, err)

		err = filter.Parse("=2147483648") // MaxInt32 + 1
		assert.Error(t, err)
	})

	// Test negative values for unsigned filters
	t.Run("unsigned negative validation", func(t *testing.T) {
		filter := NewUIntFilter()

		// Negative values should be rejected during parsing for unsigned
		err := filter.Parse("=-1")
		assert.Error(t, err)
	})
}

func TestNumericFilterEdgeCases(t *testing.T) {
	t.Parallel()

	// Test uint<0 which should be invalid
	t.Run("uint less than 0", func(t *testing.T) {
		filter := NewUIntFilter()
		err := filter.Parse("<0")
		assert.Error(t, err)
	})

	// Test uint<=0 which should be valid and only match 0
	t.Run("uint less than or equal to 0", func(t *testing.T) {
		filter := NewUIntFilter()
		err := filter.Parse("<=0")
		require.NoError(t, err)

		// Should match 0
		assert.True(t, filter.Filter(uint64(0)))
		// Should not match any positive value
		assert.False(t, filter.Filter(uint64(1)))
		assert.False(t, filter.Filter(uint64(42)))
	})

	// Test filter with wrong type
	t.Run("wrong type filtering", func(t *testing.T) {
		filter := NewIntFilter()
		err := filter.Parse("=42")
		require.NoError(t, err)

		// Try to filter with wrong type
		result := filter.Filter("not a number")
		assert.False(t, result)

		result = filter.Filter(uint64(42)) // wrong numeric type
		assert.False(t, result)
	})

	// Test clone with nil
	t.Run("clone nil filter", func(t *testing.T) {
		var filter *NumericFilter[int64]
		cloned := filter.Clone()
		assert.Nil(t, cloned)
	})
}

// Test cases for type safety improvements
func TestNumericFilterTypeSafety(t *testing.T) {
	t.Parallel()

	// Test that the new API is type-safe
	t.Run("type safety improvements", func(t *testing.T) {
		// Test 1: Equalities() on unsigned types is now type-safe
		uintFilter := NewUIntFilter()
		largeVal := uint64(math.MaxInt64) + 1000
		err := uintFilter.Parse(fmt.Sprintf("=%d", largeVal))
		require.NoError(t, err)

		eqs := uintFilter.Equalities()
		assert.Contains(t, eqs.Equal, largeVal, "Large uint64 values are preserved without corruption")
		assert.IsType(t, map[uint64]struct{}{}, eqs.Equal, "Equal map has correct uint64 type")

		// Test 2: Type-safe Minimum() on signed types
		intFilter := NewIntFilter()
		err = intFilter.Parse(">-100")
		require.NoError(t, err)

		minInt := intFilter.Minimum()
		assert.Equal(t, int64(-100), minInt, "Minimum() returns the correct typed value")
		assert.IsType(t, int64(0), minInt, "Minimum has correct int64 type")
	})

	// Edge case in unsigned parsing (<=0)
	t.Run("unsigned parsing edge cases", func(t *testing.T) {
		filter := NewUIntFilter()

		// <=0 should be valid for unsigned types (only matches 0)
		err := filter.Parse("<=0")
		assert.NoError(t, err, "<=0 should be valid for unsigned types")

		// Verify it only matches 0
		assert.True(t, filter.Filter(uint64(0)), "<=0 should match 0")
		assert.False(t, filter.Filter(uint64(1)), "<=0 should not match 1")

		// But <0 should be invalid for unsigned types
		filter2 := NewUIntFilter()
		err = filter2.Parse("<0")
		assert.Error(t, err, "<0 should be invalid for unsigned types")

		// And =0 should be valid
		filter3 := NewUIntFilter()
		err = filter3.Parse("=0")
		assert.NoError(t, err, "=0 should be valid for unsigned types")
	})
}

func TestIsUnsignedType(t *testing.T) {
	t.Parallel()

	t.Run("unsigned types", func(t *testing.T) {
		assert.True(t, isUnsignedType[uint32](), "uint32 should be unsigned")
		assert.True(t, isUnsignedType[uint64](), "uint64 should be unsigned")
	})

	t.Run("signed types", func(t *testing.T) {
		assert.False(t, isUnsignedType[int32](), "int32 should be signed")
		assert.False(t, isUnsignedType[int64](), "int64 should be signed")
	})
}
