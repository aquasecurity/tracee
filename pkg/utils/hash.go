package utils

import (
	"encoding/binary"
	"unsafe"
)

// MurMurHash 3 x86 32-bit (https://en.wikipedia.org/wiki/MurmurHash): Small (u32), simple (for C
// and Go), high performant, optimized and collision resistant hashing function. This function is
// used to hash a task unique identifier (task pid + task_start_time). Userland uses this unique
// identifier to identify a task and construct the process tree.

const (
	murmurSeed = 0x18273645 // same as in eBPF kernel code
)

// Murmur32 is a Murmur3 32-bit hash function implementation.
func Murmur32(key []byte) uint32 {
	data := key
	nblocks := len(data) / 4

	h1 := uint32(murmurSeed)
	c1 := uint32(0xcc9e2d51)
	c2 := uint32(0x1b873593)

	// Body
	blocks := data[:nblocks*4]

	for i := 0; i < nblocks; i++ {
		k1 := *(*uint32)(unsafe.Pointer(&blocks[i*4]))

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	// Tail
	tail := data[nblocks*4:]
	k1 := uint32(0)

	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// Final
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return h1
}

// HashU32AndU64 is a wrapper around Murmur32 making sure network byte order is used.
func HashU32AndU64(arg1 uint32, arg2 uint64) uint32 {
	buffer := make([]byte, 4+8)                  // u32 + u64
	binary.BigEndian.PutUint32(buffer, arg1)     // network byte order
	binary.BigEndian.PutUint64(buffer[4:], arg2) // network byte order
	return Murmur32(buffer)
}

// HashTaskID is a wrapper, around HashU32AndU64, that rounds up the timestamp argument to the
// precision userland will obtain from the procfs (since start_time is measured in clock ticks).
// This is needed so the process tree can be updated by procfs readings as well. The userland
// precision is defined by USER_HZ, which is 100HZ in almost all cases (untrue for embedded systems
// and custom kernels).

func HashTaskID(arg1 uint32, arg2 uint64) uint32 {
	round := arg2 / 10000000 // (1000000000 / USER_HZ) = 10000000
	round *= 10000000
	return HashU32AndU64(arg1, round)
}
