#ifndef __COMMON_PROG_H__
#define __COMMON_PROG_H__

#include <vmlinux.h>

#include <common/common.h>

#define BPF_PROG_LOAD 5

static __always_inline u32 get_attr_insn_cnt(union bpf_attr *attr)
{
    return READ_KERN(attr->insn_cnt);
}

static __always_inline const struct bpf_insn *get_attr_insns(union bpf_attr *attr)
{
    return (const struct bpf_insn *) READ_KERN(attr->insns);
}

#endif
