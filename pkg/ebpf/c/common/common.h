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

// Workaround: Newer LLVM versions might fail to optimize has_prefix()
// loop unrolling with the following error:
//
//     warning: loop not unrolled: the optimizer was unable to perform
//     the requested transformation; the transformation might be
//     disabled or specified as part of an unsupported transformation
//     ordering
//

#if defined(__clang__) && __clang_major__ > 13

    #define has_prefix(p, s, n)                                                                    \
        ({                                                                                         \
            int rc = 0;                                                                            \
            char *pre = p, *str = s;                                                               \
            _Pragma("unroll") for (int z = 0; z < n; pre++, str++, z++)                            \
            {                                                                                      \
                if (!*pre) {                                                                       \
                    rc = 1;                                                                        \
                    break;                                                                         \
                } else if (*pre != *str) {                                                         \
                    rc = 0;                                                                        \
                    break;                                                                         \
                }                                                                                  \
            }                                                                                      \
            rc;                                                                                    \
        })

#else

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

    // prefix is too long
    return 0;
}

#endif

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