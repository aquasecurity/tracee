#ifndef __TRACEE_BPF_H__
#define __TRACEE_BPF_H__

#define BPF_PROG_LOAD 5

static __always_inline u32 get_attr_insn_cnt(union bpf_attr *attr)
{
    return READ_KERN(attr->insn_cnt);
}

static __always_inline const struct bpf_insn *get_attr_insns(union bpf_attr *attr)
{
    return (const struct bpf_insn *) READ_KERN(attr->insns);
}

#endif // __TRACEE_BPF_H__