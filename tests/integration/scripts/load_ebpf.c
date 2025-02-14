#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Define missing BPF helper macros
#define BPF_MOV64_IMM(DST, IMM) \
    (struct bpf_insn){ BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM }

#define BPF_EXIT_INSN() \
    (struct bpf_insn){ BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_prog_load(const char *prog_name) {
    struct bpf_insn prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0), // R0 = 0
        BPF_EXIT_INSN()              // return R0
    };

    char license[] = "GPL";
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_TRACEPOINT, // Use TRACEPOINT for easier testing
        .insn_cnt = sizeof(prog) / sizeof(struct bpf_insn),
        .insns = (__aligned_u64)(uintptr_t)prog,
        .license = (__aligned_u64)(uintptr_t)license,
    };

    // Set program name
    strncpy((char *)attr.prog_name, prog_name, BPF_OBJ_NAME_LEN - 1);

    int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("BPF_PROG_LOAD failed");
        return -1;
    }

    printf("eBPF program '%s' loaded successfully! FD: %d\n", prog_name, prog_fd);
    return prog_fd;
}

int bpf_map_create(const char *map_name, enum bpf_map_type type, uint32_t key_size, uint32_t value_size, uint32_t max_entries) {
    union bpf_attr attr = {
        .map_type = type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };

    // Set map name
    strncpy((char *)attr.map_name, map_name, BPF_OBJ_NAME_LEN - 1);

    int map_fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map_fd < 0) {
        perror("BPF_MAP_CREATE failed");
        return -1;
    }

    printf("eBPF map '%s' created successfully! FD: %d\n", map_name, map_fd);
    return map_fd;
}

int main() {
    // Load eBPF program
    int prog_fd = bpf_prog_load("ebpf_prog_test");
    if (prog_fd < 0) return 1;

    // Create eBPF map
    int map_fd = bpf_map_create("ebpf_map_test", BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 100);
    if (map_fd < 0) return 1;

    return 0;
}

