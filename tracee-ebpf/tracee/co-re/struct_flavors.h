#ifndef __VMLINUX_FLAVORED_H__
#define __VMLINUX_FLAVORED_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

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
        union { };
    };
};

// commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")

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

// support bpf_core_type_exists((task struct)->pids) for kernels < 5.0

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
    __PIDTYPE_TGID
};

struct pid_link
{
    struct hlist_node node;
    struct pid *pid;
};

struct task_struct___older_v50 {
    struct pid_link pids[PIDTYPE_MAX];
};

#pragma clang attribute pop

#endif
