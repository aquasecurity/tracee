// +build ignore

// SPDX-License-Identifier: GPL-2.0
// Kprobe BPF check program - sanity check for BPF functionality

#include "lsm_check_common.h"

// Kprobe hook on security_bpf function - sanity check for BPF environment
SEC("kprobe/security_bpf")
int BPF_KPROBE(security_bpf_kprobe)
{
    (void) ctx; // Suppress unused parameter warning from BPF_KPROBE macro

    __u32 key = 0;
    __u8 triggered = 1;

    // Set flag to signal we were called
    bpf_map_update_elem(&check_result_map, &key, &triggered, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
