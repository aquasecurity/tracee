package bitwise

import "testing"

func TestHasBit(t *testing.T) {
	tests := []struct {
		name     string
		n        uint64
		offset   uint
		expected bool
	}{
		{
			name:     "bit 0 set",
			n:        1, // binary: 0001
			offset:   0,
			expected: true,
		},
		{
			name:     "bit 0 not set",
			n:        2, // binary: 0010
			offset:   0,
			expected: false,
		},
		{
			name:     "bit 1 set",
			n:        2, // binary: 0010
			offset:   1,
			expected: true,
		},
		{
			name:     "bit 1 not set",
			n:        1, // binary: 0001
			offset:   1,
			expected: false,
		},
		{
			name:     "high bit set",
			n:        1 << 63, // highest bit set
			offset:   63,
			expected: true,
		},
		{
			name:     "high bit not set",
			n:        1 << 62, // second highest bit set
			offset:   63,
			expected: false,
		},
		{
			name:     "multiple bits set - check existing",
			n:        0b1010, // binary: 1010 (bits 1 and 3 set)
			offset:   3,
			expected: true,
		},
		{
			name:     "multiple bits set - check non-existing",
			n:        0b1010, // binary: 1010 (bits 1 and 3 set)
			offset:   2,
			expected: false,
		},
		{
			name:     "zero value",
			n:        0,
			offset:   5,
			expected: false,
		},
		{
			name:     "all bits set",
			n:        ^uint64(0), // all bits set
			offset:   32,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasBit(tt.n, tt.offset)
			if result != tt.expected {
				t.Errorf("HasBit(%d, %d) = %v, expected %v", tt.n, tt.offset, result, tt.expected)
			}
		})
	}
}

func TestSetBit(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint64
		offset   uint
		expected uint64
	}{
		{
			name:     "set bit 0 on zero",
			initial:  0,
			offset:   0,
			expected: 1,
		},
		{
			name:     "set bit 1 on zero",
			initial:  0,
			offset:   1,
			expected: 2,
		},
		{
			name:     "set bit 3 on zero",
			initial:  0,
			offset:   3,
			expected: 8,
		},
		{
			name:     "set bit on already set bit",
			initial:  1, // bit 0 already set
			offset:   0,
			expected: 1, // should remain the same
		},
		{
			name:     "set additional bit",
			initial:  1, // bit 0 set
			offset:   2,
			expected: 5, // binary: 0101 (bits 0 and 2 set)
		},
		{
			name:     "set high bit",
			initial:  0,
			offset:   63,
			expected: 1 << 63,
		},
		{
			name:     "set bit on existing pattern",
			initial:  0b1010, // binary: 1010
			offset:   0,
			expected: 0b1011, // binary: 1011
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.initial
			SetBit(&n, tt.offset)
			if n != tt.expected {
				t.Errorf("SetBit(&%d, %d) resulted in %d, expected %d", tt.initial, tt.offset, n, tt.expected)
			}
		})
	}
}

func TestClearBit(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint64
		offset   uint
		expected uint64
	}{
		{
			name:     "clear bit 0 when set",
			initial:  1, // binary: 0001
			offset:   0,
			expected: 0,
		},
		{
			name:     "clear bit 1 when set",
			initial:  2, // binary: 0010
			offset:   1,
			expected: 0,
		},
		{
			name:     "clear bit when not set",
			initial:  2, // binary: 0010 (bit 1 set, bit 0 not set)
			offset:   0,
			expected: 2, // should remain unchanged
		},
		{
			name:     "clear one bit from multiple",
			initial:  0b1111, // binary: 1111 (all lower 4 bits set)
			offset:   2,
			expected: 0b1011, // binary: 1011 (bit 2 cleared)
		},
		{
			name:     "clear high bit",
			initial:  1 << 63, // highest bit set
			offset:   63,
			expected: 0,
		},
		{
			name:     "clear from complex pattern",
			initial:  0b10101010, // alternating pattern
			offset:   3,
			expected: 0b10100010, // bit 3 cleared
		},
		{
			name:     "clear from zero",
			initial:  0,
			offset:   5,
			expected: 0, // should remain zero
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.initial
			ClearBit(&n, tt.offset)
			if n != tt.expected {
				t.Errorf("ClearBit(&%d, %d) resulted in %d, expected %d", tt.initial, tt.offset, n, tt.expected)
			}
		})
	}
}

func TestClearBits(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint64
		mask     uint64
		expected uint64
	}{
		{
			name:     "clear single bit with mask",
			initial:  0b1111, // binary: 1111
			mask:     0b0001, // clear bit 0
			expected: 0b1110, // binary: 1110
		},
		{
			name:     "clear multiple bits with mask",
			initial:  0b1111, // binary: 1111
			mask:     0b1010, // clear bits 1 and 3
			expected: 0b0101, // binary: 0101
		},
		{
			name:     "clear all bits",
			initial:  0b1111, // binary: 1111
			mask:     0b1111, // clear all bits
			expected: 0b0000, // binary: 0000
		},
		{
			name:     "clear with zero mask",
			initial:  0b1111, // binary: 1111
			mask:     0b0000, // clear no bits
			expected: 0b1111, // should remain unchanged
		},
		{
			name:     "clear non-existing bits",
			initial:  0b0101, // binary: 0101 (bits 0 and 2 set)
			mask:     0b1010, // try to clear bits 1 and 3 (not set)
			expected: 0b0101, // should remain unchanged
		},
		{
			name:     "clear from zero",
			initial:  0,
			mask:     0b1111,
			expected: 0, // should remain zero
		},
		{
			name:     "clear complex pattern",
			initial:  0b11110000, // binary: 11110000
			mask:     0b10100000, // clear bits 5 and 7
			expected: 0b01010000, // binary: 01010000
		},
		{
			name:     "clear high bits",
			initial:  ^uint64(0),                         // all bits set
			mask:     uint64(0xFF) << 56,                 // clear top 8 bits
			expected: ^uint64(0) & ^(uint64(0xFF) << 56), // all bits except top 8
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.initial
			ClearBits(&n, tt.mask)
			if n != tt.expected {
				t.Errorf("ClearBits(&%d, %d) resulted in %d, expected %d", tt.initial, tt.mask, n, tt.expected)
			}
		})
	}
}

// Test integration scenarios combining multiple operations
func TestBitwiseOperationsCombined(t *testing.T) {
	t.Run("set and check bit", func(t *testing.T) {
		var n uint64
		offset := uint(5)

		// Initially bit should not be set
		if HasBit(n, offset) {
			t.Errorf("Bit %d should not be set initially", offset)
		}

		// Set the bit
		SetBit(&n, offset)

		// Now bit should be set
		if !HasBit(n, offset) {
			t.Errorf("Bit %d should be set after SetBit", offset)
		}

		// Expected value should be 2^5 = 32
		if n != 32 {
			t.Errorf("Expected value 32, got %d", n)
		}
	})

	t.Run("set and clear bit", func(t *testing.T) {
		var n uint64
		offset := uint(3)

		// Set the bit
		SetBit(&n, offset)
		if !HasBit(n, offset) {
			t.Errorf("Bit %d should be set", offset)
		}

		// Clear the bit
		ClearBit(&n, offset)
		if HasBit(n, offset) {
			t.Errorf("Bit %d should be cleared", offset)
		}

		// Should be back to zero
		if n != 0 {
			t.Errorf("Expected value 0, got %d", n)
		}
	})

	t.Run("complex operations", func(t *testing.T) {
		var n uint64

		// Set multiple bits
		SetBit(&n, 0)
		SetBit(&n, 2)
		SetBit(&n, 4)
		// n should now be 0b10101 = 21

		if n != 21 {
			t.Errorf("Expected value 21, got %d", n)
		}

		// Check each bit
		if !HasBit(n, 0) || !HasBit(n, 2) || !HasBit(n, 4) {
			t.Errorf("Bits 0, 2, 4 should be set")
		}
		if HasBit(n, 1) || HasBit(n, 3) || HasBit(n, 5) {
			t.Errorf("Bits 1, 3, 5 should not be set")
		}

		// Clear using mask (clear bits 0 and 4)
		ClearBits(&n, 0b10001) // binary: 10001

		// Now only bit 2 should be set (value = 4)
		if n != 4 {
			t.Errorf("Expected value 4, got %d", n)
		}
		if !HasBit(n, 2) {
			t.Errorf("Bit 2 should still be set")
		}
		if HasBit(n, 0) || HasBit(n, 4) {
			t.Errorf("Bits 0 and 4 should be cleared")
		}
	})
}
