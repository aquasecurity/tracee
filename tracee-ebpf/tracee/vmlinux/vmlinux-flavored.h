#ifndef __VMLINUX_FLAVORED_H__
#define __VMLINUX_FLAVORED_H__

#include <vmlinux-core.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

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

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif
