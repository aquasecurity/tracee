#ifndef __TRACEE_KCONFIG_H__
#define __TRACEE_KCONFIG_H__

#ifndef CORE
    #include <linux/types.h>
#else
    #include <vmlinux.h>
#endif

#include <bpf/bpf_helpers.h>

#ifdef CORE
    #define get_kconfig(x) get_kconfig_val(x)
#else
    #define get_kconfig(x) CONFIG_##x
#endif

#ifdef CORE

enum kconfig_key_e
{
    ARCH_HAS_SYSCALL_WRAPPER = 1000U
};

#else

    #ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
        #define CONFIG_ARCH_HAS_SYSCALL_WRAPPER 0
    #endif

#endif // CORE

static __always_inline int get_kconfig_val(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&kconfig_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

#endif