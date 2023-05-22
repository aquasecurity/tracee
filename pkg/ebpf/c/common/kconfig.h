#ifndef __COMMON_KCONFIG_H__
#define __COMMON_KCONFIG_H__

#include <vmlinux.h>

#include <common/common.h>

// TYPES

enum kconfig_key_e
{
    ARCH_HAS_SYSCALL_WRAPPER = 1000U
};

// PROTOTYPES

#define get_kconfig(x) get_kconfig_val(x)

// FUNCTIONS

statfunc int get_kconfig_val(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&kconfig_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

#endif
