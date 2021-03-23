//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    int process = 2021;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &process, sizeof(int));

    return 0;
}
