package stringutil

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

func TestReverseString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "olleh",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "a",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "palindrome",
			input:    "racecar",
			expected: "racecar",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "dlrow olleh",
		},
		{
			name:     "string with numbers",
			input:    "abc123",
			expected: "321cba",
		},
		{
			name:     "string with special characters",
			input:    "!@#$%^&*()",
			expected: ")(*&^%$#@!",
		},
		{
			name:     "unicode characters",
			input:    "héllo",
			expected: "oll\xa9\xc3h", // Byte-level reverse (é = 0xC3 0xA9 in UTF-8)
		},
		{
			name:     "emojis",
			input:    "🚀🌟",
			expected: "\x9f\x8c\x9f\xf0\x80\x9a\x9f\xf0", // Byte-level reverse
		},
		{
			name:     "mixed case",
			input:    "Hello World",
			expected: "dlroW olleH",
		},
		{
			name:     "long string",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "god yzal eht revo spmuj xof nworb kciuq ehT",
		},
		{
			name:     "string with newlines",
			input:    "line1\nline2",
			expected: "2enil\n1enil",
		},
		{
			name:     "string with tabs",
			input:    "col1\tcol2",
			expected: "2loc\t1loc",
		},
		{
			name:     "repeated characters",
			input:    "aaabbbccc",
			expected: "cccbbbaaa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReverseString(tt.input)
			require.Equal(t, tt.expected, result)

			// Double reverse should give original string for all cases
			if tt.input != "" { // Skip double reverse test for empty string as it's redundant
				doubleReverse := ReverseString(result)
				require.Equal(t, tt.input, doubleReverse, "Double reverse should equal original")
			}
		})
	}
}

// Test that ReverseString preserves memory properties
func TestReverseString_MemoryProperties(t *testing.T) {
	t.Parallel()

	t.Run("result is independent of input", func(t *testing.T) {
		input := "test"
		result := ReverseString(input)

		// The result should be a new string, not sharing memory
		// We can't easily test this directly, but we can verify behavior
		require.Equal(t, "tset", result)
		require.Equal(t, "test", input) // Original unchanged
	})

	t.Run("handles zero-length input", func(t *testing.T) {
		result := ReverseString("")
		require.Equal(t, "", result)
		require.Equal(t, 0, len(result))
	})

	t.Run("proper byte handling", func(t *testing.T) {
		// Test that byte-level operations work correctly
		input := "ABC"
		result := ReverseString(input)
		require.Equal(t, "CBA", result)
		require.Equal(t, 3, len(result))
		require.Equal(t, byte('C'), result[0])
		require.Equal(t, byte('B'), result[1])
		require.Equal(t, byte('A'), result[2])
	})
}

// Additional tests for TrimTrailingNUL edge cases
func TestTrimTrailingNUL_AdditionalCases(t *testing.T) {
	t.Parallel()

	t.Run("memory sharing verification", func(t *testing.T) {
		original := []byte("hello\x00\x00")
		result := TrimTrailingNUL(original)

		// Result should share memory with original (slice of original)
		require.Equal(t, []byte("hello"), result)

		// Modifying the shared part should affect both
		if len(result) > 0 {
			result[0] = 'H'
			require.Equal(t, byte('H'), original[0])
		}
	})

	t.Run("single NUL byte", func(t *testing.T) {
		input := []byte{0}
		result := TrimTrailingNUL(input)
		require.Equal(t, []byte{}, result)
		require.Equal(t, 0, len(result))
	})

	t.Run("nil slice", func(t *testing.T) {
		var input []byte
		result := TrimTrailingNUL(input)
		require.Nil(t, result)
	})

	t.Run("large input with trailing NULs", func(t *testing.T) {
		// Create a large slice with content followed by many NULs
		content := make([]byte, 1000)
		for i := range content {
			content[i] = byte('A' + (i % 26))
		}

		// Add trailing NULs
		input := append(content, make([]byte, 100)...) // 100 trailing NULs
		result := TrimTrailingNUL(input)

		require.Equal(t, content, result)
		require.Equal(t, 1000, len(result))
	})

	t.Run("binary data with NULs", func(t *testing.T) {
		// Test with actual binary data that might contain NULs
		input := []byte{0x01, 0x02, 0x00, 0x03, 0x04, 0x00, 0x00}
		expected := []byte{0x01, 0x02, 0x00, 0x03, 0x04}
		result := TrimTrailingNUL(input)
		require.Equal(t, expected, result)
	})
}

// Test both functions working together
func TestStringUtilIntegration(t *testing.T) {
	t.Parallel()

	t.Run("reverse string and trim NULs", func(t *testing.T) {
		// Create a string, add NULs, reverse, then trim
		original := "hello"
		withNULs := append([]byte(original), 0, 0, 0)

		// Reverse the bytes (including NULs)
		reversed := make([]byte, len(withNULs))
		for i := 0; i < len(withNULs); i++ {
			reversed[len(withNULs)-i-1] = withNULs[i]
		}

		// Trim trailing NULs (which are now leading NULs after reverse)
		// Wait, that doesn't make sense for this function. Let me fix this.

		// Actually, let's do a meaningful integration test:
		// Start with a byte slice that has content + trailing NULs,
		// trim the NULs, convert to string, then reverse

		input := []byte("world\x00\x00\x00")
		trimmed := TrimTrailingNUL(input)
		asString := string(trimmed)
		reversedString := ReverseString(asString)

		require.Equal(t, "dlrow", reversedString)
	})

	t.Run("reverse then convert to bytes with NULs", func(t *testing.T) {
		original := "test"
		reversedStr := ReverseString(original)
		require.Equal(t, "tset", reversedStr)

		// Convert to bytes and add NULs
		withNULs := append([]byte(reversedStr), 0, 0)
		trimmed := TrimTrailingNUL(withNULs)

		require.Equal(t, []byte("tset"), trimmed)
	})
}
