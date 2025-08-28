package stringutil

// ReverseString returns a reversed copy of the input string.
func ReverseString(s string) string {
	n := len(s)
	bytes := make([]byte, n)

	for i := 0; i < n; i++ {
		bytes[n-i-1] = s[i]
	}
	return string(bytes)
}

// TrimTrailingNUL returns a subslice of the input with all trailing NUL bytes (0x00) removed.
// It performs a reverse scan and returns b[:end], avoiding any allocations.
//
// This function is optimized for fixed-size, ASCII-compatible C-style buffers where padding
// with trailing NULs may occur.
//
// Note:
//   - The returned slice shares memory with the original input.
//   - If you need an independent string or slice, copy it manually.
//   - This function is not safe for UTF-8 or multibyte character data; it assumes ASCII content only.
func TrimTrailingNUL(b []byte) []byte {
	end := len(b)

	for end > 0 && b[end-1] == 0 {
		end--
	}

	return b[:end]
}
