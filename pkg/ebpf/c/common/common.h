#ifndef __TRACEE_COMMON_H__
#define __TRACEE_COMMON_H__

#include <bpf/bpf_helpers.h>
#include "maps.h"

#ifndef CORE
    #include <linux/device.h>
    #include <linux/types.h>
#else
    // CO:RE is enabled
    #include <vmlinux.h>
#endif

#ifndef CORE

    #define GET_FIELD_ADDR(field) &field

    #define READ_KERN(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_probe_read((void *) &_val, sizeof(_val), &ptr);                                    \
            _val;                                                                                  \
        })

    #define READ_KERN_STR_INTO(dst, src) bpf_probe_read_str((void *) &dst, sizeof(dst), src)

    #define READ_USER(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_probe_read_user((void *) &_val, sizeof(_val), &ptr);                               \
            _val;                                                                                  \
        })

    #define BPF_READ(src, a, ...)                                                                  \
        ({                                                                                         \
            ___type((src), a, ##__VA_ARGS__) __r;                                                  \
            BPF_PROBE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);                                    \
            __r;                                                                                   \
        })

#else // CORE
    #include <bpf/bpf_core_read.h>

    #define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

    #define READ_KERN(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_core_read((void *) &_val, sizeof(_val), &ptr);                                     \
            _val;                                                                                  \
        })

    #define READ_KERN_STR_INTO(dst, src) bpf_core_read_str((void *) &dst, sizeof(dst), src)

    #define READ_USER(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_core_read_user((void *) &_val, sizeof(_val), &ptr);                                \
            _val;                                                                                  \
        })

    #define BPF_READ(src, a, ...)                                                                  \
        ({                                                                                         \
            ___type((src), a, ##__VA_ARGS__) __r;                                                  \
            BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);                                     \
            __r;                                                                                   \
        })

#endif

// HELPERS: DEVICES --------------------------------------------------------------------------------

static __always_inline const char *get_device_name(struct device *dev)
{
    struct kobject kobj = READ_KERN(dev->kobj);
    return kobj.name;
}

// INTERNAL: STRINGS -------------------------------------------------------------------------------

static __inline int has_prefix(char *prefix, char *str, int n)
{
    int i;

#pragma unroll
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    return 0; // prefix too long
}

static __inline int has_prefix_unrolled(char *prefix, char *str, int n)
{
    // The same as "has_prefix", but caller is already unrolling external loop.
    // This avoids transformation errors from clang when unrolling twice.

    int i;

    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    return 0; // prefix too long
}

// helper macros for branch prediction
#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

// helpers for iterating over a list_head struct
#define list_entry_ebpf(ptr, type, member) container_of(ptr, type, member)

#define list_next_entry_ebpf(pos, member)                                                          \
    list_entry_ebpf(READ_KERN((pos)->member.next), typeof(*(pos)), member)

#define list_first_entry_ebpf(ptr, type, member)                                                   \
    list_entry_ebpf(READ_KERN((ptr)->next), type, member)

#endif // __TRACEE_COMMON_H__
