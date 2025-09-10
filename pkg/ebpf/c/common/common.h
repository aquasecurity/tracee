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

statfunc int has_prefix(char *prefix, char *str, int n)
{
    int i;
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    // if prefix is longer than n, return 0
    if (i == n && *prefix)
        return 0;

    // prefix and string are identical
    return 1;
}

statfunc int strncmp(char *str1, char *str2, int n)
{
    int i;
    for (i = 0; i < n; str1++, str2++, i++) {
        if (*str1 != *str2 || *str1 == '\0' || *str2 == '\0')
            return (unsigned char) *str1 - (unsigned char) *str2;
    }
    return 0;
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
    list_entry_ebpf(BPF_CORE_READ(pos, member.next), typeof(*(pos)), member)

#define list_first_entry_ebpf(ptr, type, member)                                                   \
    list_entry_ebpf(BPF_CORE_READ(ptr, next), type, member)

#ifndef update_min
    // update_min sets __var as __max_const if __var is greater than __max_const.
    // It forces the check to be done via a register, which is sometimes necessary
    // to satisfy the eBPF verifier.
    #define update_min(__var, __max_const)                                                         \
        ({                                                                                         \
            asm volatile("if %[size] <= %[max_size] goto +1;\n"                                    \
                         "%[size] = %[max_size];\n"                                                \
                         : [size] "+r"(__var)                                                      \
                         : [max_size] "r"(__max_const));                                           \
        })
#endif

#ifndef min
    #define min(x, y)                                                                              \
        ({                                                                                         \
            typeof(x) _min1 = (x);                                                                 \
            typeof(y) _min2 = (y);                                                                 \
            (void) (&_min1 == &_min2);                                                             \
            _min1 < _min2 ? _min1 : _min2;                                                         \
        })
#endif

statfunc u64 get_current_time_in_ns(void)
{
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns))
        return bpf_ktime_get_boot_ns();
    return bpf_ktime_get_ns();
}

#endif // __COMMON_COMMON_H__
