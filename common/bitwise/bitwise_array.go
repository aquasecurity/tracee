package bitwise

// Bitmap-array helpers operate on a []uint64 treated as a single contiguous
// bitmap, where bit i lives in word i/64 at offset i%64. They back the policy
// "matched rules" model, whose rule IDs may exceed 64 (one uint64 word) and
// therefore require an arbitrary-width bitmap.

// HasBitInArray returns true if the bit at the given index is set. Indices
// beyond the array length are treated as unset.
func HasBitInArray(bitmaps []uint64, index uint) bool {
	wordIndex := index / 64
	bitOffset := index % 64

	if int(wordIndex) >= len(bitmaps) {
		return false
	}

	return HasBit(bitmaps[wordIndex], bitOffset)
}

// SetBitInArray sets the bit at the given index, growing the array with
// zero-valued words as needed to reach the target word.
func SetBitInArray(bitmaps *[]uint64, index uint) {
	wordIndex := index / 64
	bitOffset := index % 64

	for len(*bitmaps) <= int(wordIndex) {
		*bitmaps = append(*bitmaps, 0)
	}

	SetBit(&(*bitmaps)[wordIndex], bitOffset)
}

// ClearBitInArray clears the bit at the given index. Indices beyond the array
// length are already unset and left untouched.
func ClearBitInArray(bitmaps *[]uint64, index uint) {
	wordIndex := index / 64
	bitOffset := index % 64

	if int(wordIndex) >= len(*bitmaps) {
		return
	}

	ClearBit(&(*bitmaps)[wordIndex], bitOffset)
}

// OrBitmapArrays ORs src into dest word-by-word, growing dest as needed so that
// every set bit of src is reflected in dest.
func OrBitmapArrays(dest *[]uint64, src []uint64) {
	for len(*dest) < len(src) {
		*dest = append(*dest, 0)
	}

	for i := 0; i < len(src); i++ {
		(*dest)[i] |= src[i]
	}
}

// IsBitmapArrayEmpty returns true if no bit is set in the array.
func IsBitmapArrayEmpty(bitmaps []uint64) bool {
	for _, bitmap := range bitmaps {
		if bitmap != 0 {
			return false
		}
	}
	return true
}
