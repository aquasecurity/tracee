// +build ignore

// SPDX-License-Identifier: GPL-2.0
// LSM BPF check program - isolated LSM hook only

#include "lsm_check_common.h"

// LSM hook for BPF operations - triggers for most bpf operations including map operations
SEC("lsm/bpf")
int BPF_PROG(lsm_bpf_check)
{
    (void) ctx; // Suppress unused parameter warning from BPF_PROG macro

    __u32 key = 0;
    __u8 triggered = 1;

    // Set flag to signal we were called
    bpf_map_update_elem(&check_result_map, &key, &triggered, BPF_ANY);

    // Always allow the BPF operation
    return 0;
}

char _license[] SEC("license") = "GPL";
