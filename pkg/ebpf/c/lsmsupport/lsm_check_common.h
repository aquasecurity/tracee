// SPDX-License-Identifier: GPL-2.0
// Shared definitions for LSM and kprobe BPF checks

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Map to store check results for isolated BPF program checking
// Each program uses key 0 to indicate if its hook was triggered
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} check_result_map SEC(".maps");
