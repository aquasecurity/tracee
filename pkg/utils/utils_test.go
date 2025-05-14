package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrimTrailingNUL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "no NUL",
			input:    []byte("hello"),
			expected: []byte("hello"),
		},
		{
			name:     "single trailing NUL",
			input:    []byte("hello\x00"),
			expected: []byte("hello"),
		},
		{
			name:     "multiple trailing NULs",
			input:    []byte("hello\x00\x00\x00"),
			expected: []byte("hello"),
		},
		{
			name:     "intermediate NUL (preserved)",
			input:    []byte("he\x00llo\x00"),
			expected: []byte("he\x00llo"),
		},
		{
			name:     "all NULs",
			input:    []byte("\x00\x00\x00"),
			expected: []byte(""),
		},
		{
			name:     "empty slice",
			input:    []byte(""),
			expected: []byte(""),
		},
		{
			name:     "no trailing NUL but contains middle NUL",
			input:    []byte("\x00he\x00llo"),
			expected: []byte("\x00he\x00llo"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, TrimTrailingNUL(tt.input))
		})
	}
}
