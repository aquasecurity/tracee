#ifndef __VMLINUX_FLAVORED_H__
#define __VMLINUX_FLAVORED_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

union kernfs_node_id {
    struct {
        u32     ino;
        u32     generation;
    };
    u64         id;
};

struct kernfs_node___old {
    const char            *name;
    union kernfs_node_id  id;
};

struct sock___old {
    struct sock_common      __sk_common;
    unsigned int            __sk_flags_offset[0];
    unsigned int            sk_padding : 1,
                            sk_kern_sock : 1,
                            sk_no_check_tx : 1,
                            sk_no_check_rx : 1,
                            sk_userlocks : 4,
                            sk_protocol  : 8,
                            sk_type      : 16;
    u16                     sk_gso_max_segs;
};

#pragma clang attribute pop

#endif
