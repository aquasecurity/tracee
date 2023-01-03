#ifndef __TRACEE_MEMORY_H__
#define __TRACEE_MEMORY_H__
#ifndef CORE
    #include <linux/sched.h>
    #include <linux/mm_types.h>
#else
    // CO:RE is enabled
    #include <vmlinux.h>
#endif
#include <bpf/bpf_helpers.h>
#include "common/common.h"

static __always_inline struct mm_struct *get_mm_from_task(struct task_struct *task)
{
    return READ_KERN(task->mm);
}

static __always_inline unsigned long get_arg_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->arg_start);
}

static __always_inline unsigned long get_arg_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->arg_end);
}

static __always_inline unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_start);
}

static __always_inline unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_end);
}

static __always_inline unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return READ_KERN(vma->vm_flags);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

#endif