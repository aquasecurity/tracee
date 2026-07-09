package bitwise

import (
	"testing"
)

func TestSetAndHasBitInArray(t *testing.T) {
	var bitmaps []uint64

	// Bits chosen to exercise the cross-word boundary (>= 64), which is the
	// reason the array variant exists.
	indices := []uint{0, 63, 64, 65, 127, 128, 200}
	for _, i := range indices {
		SetBitInArray(&bitmaps, i)
	}

	for _, i := range indices {
		if !HasBitInArray(bitmaps, i) {
			t.Errorf("expected bit %d to be set", i)
		}
	}

	// Neighbors of set bits must remain unset.
	for _, i := range []uint{1, 62, 66, 129, 199, 201} {
		if HasBitInArray(bitmaps, i) {
			t.Errorf("expected bit %d to be unset", i)
		}
	}

	// index 200 -> word 3, so the array must have grown to 4 words.
	if len(bitmaps) != 4 {
		t.Errorf("expected array to grow to 4 words, got %d", len(bitmaps))
	}
}

func TestHasBitInArrayOutOfRange(t *testing.T) {
	bitmaps := []uint64{} // empty
	if HasBitInArray(bitmaps, 0) {
		t.Error("empty array must report bit 0 unset")
	}
	if HasBitInArray(bitmaps, 1000) {
		t.Error("out-of-range index must report unset")
	}
}

func TestClearBitInArray(t *testing.T) {
	var bitmaps []uint64
	SetBitInArray(&bitmaps, 70)
	SetBitInArray(&bitmaps, 71)

	ClearBitInArray(&bitmaps, 70)
	if HasBitInArray(bitmaps, 70) {
		t.Error("bit 70 should be cleared")
	}
	if !HasBitInArray(bitmaps, 71) {
		t.Error("bit 71 should remain set")
	}

	// Clearing an out-of-range bit must be a no-op (not panic, not grow).
	prevLen := len(bitmaps)
	ClearBitInArray(&bitmaps, 100000)
	if len(bitmaps) != prevLen {
		t.Error("clearing out-of-range bit must not grow the array")
	}
}

func TestOrBitmapArrays(t *testing.T) {
	dest := []uint64{0b0001}
	src := []uint64{0b0010, 0b1000} // src is wider than dest

	OrBitmapArrays(&dest, src)

	if dest[0] != 0b0011 {
		t.Errorf("word 0: expected 0b0011, got %b", dest[0])
	}
	if len(dest) != 2 || dest[1] != 0b1000 {
		t.Errorf("dest must grow to absorb src's high word, got %v", dest)
	}
}

func TestIsBitmapArrayEmpty(t *testing.T) {
	if !IsBitmapArrayEmpty(nil) {
		t.Error("nil array must be empty")
	}
	if !IsBitmapArrayEmpty([]uint64{0, 0, 0}) {
		t.Error("all-zero array must be empty")
	}

	var bitmaps []uint64
	SetBitInArray(&bitmaps, 130)
	if IsBitmapArrayEmpty(bitmaps) {
		t.Error("array with a set bit must not be empty")
	}
}
