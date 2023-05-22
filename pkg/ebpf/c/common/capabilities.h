#ifndef __COMMON_CAPABILITIES_H__
#define __COMMON_CAPABILITIES_H__

#include <vmlinux.h>
#include <vmlinux_flavors.h>

#include <common/common.h>

// PROTOTYPES

statfunc u64 credcap_to_slimcap(void *);

// FUNCTIONS

// BEFORE: Currently, (2021), there are ~40 capabilities in the Linux kernel
// which are stored in an u32 array of length 2. This might change in the (not
// so near) future as more capabilities will be added. For now, we use u64 to
// store this array in one piece
//
// NEW NOTE: Recently, (2023), kernel has started using an u64 for all
// capabilities, instead of using variable u32 array. Use type flavors to
// deal with that.
//

statfunc u64 credcap_to_slimcap(void *from)
{
    kernel_cap_t___older to = {0};

    if (bpf_core_field_exists(to.cap)) {
        bpf_core_read(&to, bpf_core_type_size(kernel_cap_t___older), from);
        return ((to.cap[1] + 0ULL) << 32) + to.cap[0];

    } else {
        kernel_cap_t newto = {0};
        bpf_core_read(&newto, bpf_core_type_size(kernel_cap_t), from);
        return newto.val;
    }

    return 0;
}

#endif
