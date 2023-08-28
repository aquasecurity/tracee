#ifndef __COMMON_HASH_H__

#define __COMMON_HASH_H__

#include "bpf/bpf_endian.h"
#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/common.h>

#define MURMUR_SEED ((u32) 0x18273645) // same as in userland

// PROTOTYPES

u32 murmur32(const void *, u32);
u32 hash_u32_and_u64(u32, u64);

// FUNCTIONS

// MurMurHash 3 x86 32-bit (https://en.wikipedia.org/wiki/MurmurHash): Small (u32), simple (for C
// and Go), high performant, optimized and collision resistant hashing function. This function is
// used to hash a task unique identifier (task pid + task_start_time). Userland uses this unique
// identifier to identify a task and construct the process tree.

// Murmur3 32-bit hash function implementation.

u32 murmur32(const void *key, u32 len)
{
    const u8 *data = (const u8 *) key;
    const int nblocks = len / 4;

    u32 h1 = MURMUR_SEED;
    u32 c1 = 0xcc9e2d51;
    u32 c2 = 0x1b873593;

    // Body
    const u32 *blocks = (const u32 *) (data + nblocks * 4);

    for (int i = -nblocks; i; i++) {
        u32 k1 = blocks[i];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Tail
    const u8 *tail = (const u8 *) (data + nblocks * 4);
    u32 k1 = 0;

    switch (len & 3) {
        case 3:
            k1 ^= tail[2] << 16;
        case 2:
            k1 ^= tail[1] << 8;
        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = (k1 << 15) | (k1 >> 17);
            k1 *= c2;
            h1 ^= k1;
    };

    // Final
    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

// Hash a u32 and a u64 into a u32. This function is used to hash a task unique identifier.
// Identical to Golang (userland) HashU32AndU64 function: same hash for same input.

u32 hash_u32_and_u64(u32 arg1, u64 arg2)
{
    uint8_t buffer[sizeof(arg1) + sizeof(arg2)];

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    arg1 = __builtin_bswap32(arg1); // network byte order is big endian, convert for ...
    arg2 = __builtin_bswap64(arg2); // ... consistent hashing among different endianness.
#endif

    __builtin_memcpy(buffer, &arg1, sizeof(arg1));
    __builtin_memcpy(buffer + sizeof(arg1), &arg2, sizeof(arg2));

    return murmur32(buffer, 4 + 8); // 4 + 8 = sizeof(u32) + sizeof(u64)
}

// hash_task_id is a wrapper, around HashU32AndU64, that rounds up the timestamp argument to the
// precision userland will obtain from the procfs (since start_time is measured in clock ticks).
// This is needed so the process tree can be updated by procfs readings as well. The userland
// precision is defined by USER_HZ, which is 100HZ in almost all cases (untrue for embedded systems

u32 hash_task_id(u32 arg1, u64 arg2)
{
    u64 round = arg2 / 10000000LL; // (1000000000 / USER_HZ) = 10000000
    round *= 10000000LL;
    return hash_u32_and_u64(arg1, round);
}

#endif
