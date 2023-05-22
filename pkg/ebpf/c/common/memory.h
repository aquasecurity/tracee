#ifndef __COMMON_MEMORY_H__
#define __COMMON_MEMORY_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc struct mm_struct *get_mm_from_task(struct task_struct *);
statfunc unsigned long get_arg_start_from_mm(struct mm_struct *);
statfunc unsigned long get_arg_end_from_mm(struct mm_struct *);
statfunc unsigned long get_env_start_from_mm(struct mm_struct *);
statfunc unsigned long get_env_end_from_mm(struct mm_struct *);
statfunc unsigned long get_vma_flags(struct vm_area_struct *);

// FUNCTIONS

statfunc struct mm_struct *get_mm_from_task(struct task_struct *task)
{
    return READ_KERN(task->mm);
}

statfunc unsigned long get_arg_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->arg_start);
}

statfunc unsigned long get_arg_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->arg_end);
}

statfunc unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_start);
}

statfunc unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_end);
}

statfunc unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return READ_KERN(vma->vm_flags);
}

statfunc struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

#endif
