package bitwise

// HasBit returns true if the bit at the given offset is set.
func HasBit(n uint64, offset uint) bool {
	return (n & (1 << offset)) > 0
}

// ClearBit clears the bit at the given offset.
func ClearBit(n *uint64, offset uint) {
	*n &= ^(1 << offset)
}

// ClearBits clears all bits specified by the mask.
func ClearBits(n *uint64, mask uint64) {
	*n &= ^mask
}

// SetBit sets the bit at the given offset.
func SetBit(n *uint64, offset uint) {
	*n |= (1 << offset)
}
