#ifndef __COMMON_COMMON_H__
#define __COMMON_COMMON_H__

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>

#include <maps.h>

// PROTOTYPES

#define statfunc static __always_inline

// FUNCTIONS & MACROS

statfunc const char *get_device_name(struct device *dev)
{
    struct kobject kobj = BPF_CORE_READ(dev, kobj);
    return kobj.name;
}

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
    list_entry_ebpf(BPF_CORE_READ(pos, member.next), typeof(*(pos)), member)

#define list_first_entry_ebpf(ptr, type, member)                                                   \
    list_entry_ebpf(BPF_CORE_READ(ptr, next), type, member)

#endif
