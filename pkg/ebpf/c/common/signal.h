#ifndef __COMMON_SIGNAL_H__
#define __COMMON_SIGNAL_H__

#include <vmlinux.h>

#include <types.h>
#include <common/common.h>

statfunc controlplane_signal_t *init_controlplane_signal()
{
    int zero = 0;
    controlplane_signal_t *signal = bpf_map_lookup_elem(&signal_data_map, &zero);
    if (unlikely(signal == NULL))
        return NULL;

    signal->args_buf.argnum = 0;
    signal->args_buf.offset = 0;
    return signal;
}

#endif
