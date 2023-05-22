#ifndef __COMMON_PROG_H__
#define __COMMON_PROG_H__

#include <vmlinux.h>

#include <common/common.h>

// CONSTANTS

#define BPF_PROG_LOAD 5

// PROTOTYPES

statfunc u32 get_attr_insn_cnt(union bpf_attr *);
statfunc const struct bpf_insn *get_attr_insns(union bpf_attr *);

// FUNCTIONS

statfunc u32 get_attr_insn_cnt(union bpf_attr *attr)
{
    return READ_KERN(attr->insn_cnt);
}

statfunc const struct bpf_insn *get_attr_insns(union bpf_attr *attr)
{
    return (const struct bpf_insn *) READ_KERN(attr->insns);
}

#endif
