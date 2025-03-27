package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBitOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		initialValue  uint64
		bitOffset     uint
		expectedHas   bool
		expectedClear uint64
		expectedSet   uint64
	}{
		{
			name:          "bit set at offset 0",
			initialValue:  1,
			bitOffset:     0,
			expectedHas:   true,
			expectedClear: 0,
			expectedSet:   1,
		},
		{
			name:          "bit not set at offset 1",
			initialValue:  1,
			bitOffset:     1,
			expectedHas:   false,
			expectedClear: 1,
			expectedSet:   3,
		},
		{
			name:          "bit set at offset 63",
			initialValue:  1 << 63,
			bitOffset:     63,
			expectedHas:   true,
			expectedClear: 0,
			expectedSet:   1 << 63,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test HasBit
			assert.Equal(t, tt.expectedHas, HasBit(tt.initialValue, tt.bitOffset))

			// Test ClearBit
			value := tt.initialValue
			ClearBit(&value, tt.bitOffset)
			assert.Equal(t, tt.expectedClear, value)

			// Test SetBit
			value = tt.initialValue
			SetBit(&value, tt.bitOffset)
			assert.Equal(t, tt.expectedSet, value)
		})
	}
}

func TestClearBits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		initialValue uint64
		mask         uint64
		expected     uint64
	}{
		{
			name:         "clear single bit",
			initialValue: 0xFF,
			mask:         0x01,
			expected:     0xFE,
		},
		{
			name:         "clear multiple bits",
			initialValue: 0xFF,
			mask:         0x0F,
			expected:     0xF0,
		},
		{
			name:         "clear no bits",
			initialValue: 0xFF,
			mask:         0x00,
			expected:     0xFF,
		},
		{
			name:         "clear all bits",
			initialValue: 0xFF,
			mask:         0xFF,
			expected:     0x00,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			value := tt.initialValue
			ClearBits(&value, tt.mask)
			assert.Equal(t, tt.expected, value)
		})
	}
}

func TestMinMax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		x           uint64
		y           uint64
		expectedMin uint64
		expectedMax uint64
	}{
		{
			name:        "x less than y",
			x:           5,
			y:           10,
			expectedMin: 5,
			expectedMax: 10,
		},
		{
			name:        "x greater than y",
			x:           10,
			y:           5,
			expectedMin: 5,
			expectedMax: 10,
		},
		{
			name:        "x equals y",
			x:           5,
			y:           5,
			expectedMin: 5,
			expectedMax: 5,
		},
		{
			name:        "zero values",
			x:           0,
			y:           0,
			expectedMin: 0,
			expectedMax: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.expectedMin, Min(tt.x, tt.y))
			assert.Equal(t, tt.expectedMax, Max(tt.x, tt.y))
		})
	}
}

func TestGenerateRandomDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		min  int
		max  int
	}{
		{
			name: "small range",
			min:  1,
			max:  5,
		},
		{
			name: "large range",
			min:  10,
			max:  100,
		},
		{
			name: "equal min max",
			min:  5,
			max:  5,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for i := 0; i < 100; i++ { // Run multiple times to test randomness
				duration := GenerateRandomDuration(tt.min, tt.max)
				seconds := int(duration / time.Second)
				assert.GreaterOrEqual(t, seconds, tt.min)
				assert.LessOrEqual(t, seconds, tt.max)
			}
		})
	}
}

func TestReverseString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "a",
		},
		{
			name:     "multiple characters",
			input:    "hello",
			expected: "olleh",
		},
		{
			name:     "palindrome",
			input:    "radar",
			expected: "radar",
		},
		{
			name:     "with spaces",
			input:    "hello world",
			expected: "dlrow olleh",
		},
		{
			name:     "with special characters",
			input:    "!@#$%",
			expected: "%$#@!",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := ReverseString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
