package utils

import (
	"encoding/binary"

	"github.com/twmb/murmur3"
)

const (
	MurmurSeed = 0x18273645
)

// HashU32AndU64 is a wrapper around Murmur3i386. It returns a uint32 hash of the input arguments.
func HashU32AndU64(arg1 uint32, arg2 uint64) uint32 {
	buffer := make([]byte, 4+8)                  // u32 + u64
	binary.BigEndian.PutUint32(buffer, arg1)     // network byte order
	binary.BigEndian.PutUint64(buffer[4:], arg2) // network byte order
	return Murmur3i386(buffer)
}

// Murmur3i386 is a wrapper around murmur3.SeedNew32. It returns a uint32 hash of the input key
// using the Murmur3 algorithm. The Murmur3 algorithm is known to have good distribution and
// performance characteristics for hash tables. It also has a low collision rate.
func Murmur3i386(key []byte) uint32 {
	hasher := murmur3.SeedNew32(MurmurSeed)
	hasher.Write(key)
	return hasher.Sum32()
}
