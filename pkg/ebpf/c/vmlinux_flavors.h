#ifndef __VMLINUX_FLAVORS_H__
#define __VMLINUX_FLAVORS_H__

#include <vmlinux.h>

;
; // don't remove: clangd parsing bug https://github.com/clangd/clangd/issues/1167
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

// (struct kernfs_node *)->id was union kernfs_node_id before 5.5

union kernfs_node_id {
    struct {
        u32 ino;
        u32 generation;
    };
    u64 id;
};

struct kernfs_node___older_v55 {
    const char *name;
    union kernfs_node_id id;
};

struct kernfs_node___rh8 {
    const char *name;
    union {
        u64 id;
        struct {
            union kernfs_node_id id;
        } rh_kabi_hidden_172;
        union {
        };
    };
};

// commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")

// clang-format off

struct sock___old {
    struct sock_common  __sk_common;
    unsigned int        __sk_flags_offset[0];
    unsigned int        sk_padding : 1,
                        sk_kern_sock : 1,
                        sk_no_check_tx : 1,
                        sk_no_check_rx : 1,
                        sk_userlocks : 4,
                        sk_protocol  : 8,
                        sk_type      : 16;
    u16                 sk_gso_max_segs;
};

// clang-format on

// support bpf_core_type_exists((task struct)->pids) for kernels < 5.0

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
    __PIDTYPE_TGID
};

struct pid_link {
    struct hlist_node node;
    struct pid *pid;
};

struct task_struct___older_v50 {
    struct pid_link pids[PIDTYPE_MAX];
};

struct trace_probe___v53 {
    struct trace_event_call call;
};

// kernel >= 6.1 kernel_cap_t type change

struct kernel_cap_struct___older {
    __u32 cap[2];
};

typedef struct kernel_cap_struct___older kernel_cap_t___older;

// struct module //

struct module_layout {
    void *base;
};

struct module___older_v64 {
    struct module_layout core_layout;
};

// kernel >= v6.6 inode i_ctime field change
struct inode___older_v66 {
    struct timespec64 i_ctime;
};

// kernel >= v6.11 inode i_ctime field change
struct inode___older_v611 {
    struct timespec64 __i_ctime;
};

///////////////////

#pragma clang attribute pop

#endif
