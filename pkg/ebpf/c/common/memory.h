#ifndef __COMMON_MEMORY_H__
#define __COMMON_MEMORY_H__

#include <vmlinux.h>

#include <common/common.h>

enum vma_type
{
    VMA_STACK,
    VMA_HEAP,
    VMA_ANON,
    VMA_OTHER
};

// PROTOTYPES

statfunc struct mm_struct *get_mm_from_task(struct task_struct *);
statfunc unsigned long get_arg_start_from_mm(struct mm_struct *);
statfunc unsigned long get_arg_end_from_mm(struct mm_struct *);
statfunc unsigned long get_env_start_from_mm(struct mm_struct *);
statfunc unsigned long get_env_end_from_mm(struct mm_struct *);
statfunc unsigned long get_vma_flags(struct vm_area_struct *);
statfunc struct vm_area_struct *find_vma(void *ctx, struct task_struct *task, u64 addr);
statfunc bool vma_is_stack(struct vm_area_struct *vma);
statfunc bool vma_is_heap(struct vm_area_struct *vma);
statfunc bool vma_is_anon(struct vm_area_struct *vma);
statfunc bool vma_is_vdso(struct vm_area_struct *vma);
statfunc enum vma_type get_vma_type(struct vm_area_struct *vma);

// FUNCTIONS

statfunc struct mm_struct *get_mm_from_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, mm);
}

statfunc unsigned long get_arg_start_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, arg_start);
}

statfunc unsigned long get_arg_end_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, arg_end);
}

statfunc unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, env_start);
}

statfunc unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, env_end);
}

statfunc unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_flags);
}

statfunc struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

/**
 * A busy process can have somewhere in the ballpark of 1000 VMAs.
 * In an ideally balanced tree, this means that the max depth is ~10.
 * A poorly balanced tree can have a leaf node that is up to twice as deep
 * as another leaf node, which in the worst case scenario places its depth
 * at 2*10 = 20.
 * To be extra safe and accomodate for VMA counts higher than 1000,
 * we define the max traversal depth as 25.
 */
#define MAX_VMA_RB_TREE_DEPTH 25

static bool alerted_find_vma_unsupported = false;

// Given a task, find the first VMA which contains the given address.
statfunc struct vm_area_struct *find_vma(void *ctx, struct task_struct *task, u64 addr)
{
    /**
     * TODO: from kernel version 6.1, the data structure with which VMAs
     * are managed changed from an RB tree to a maple tree.
     * We currently don't support finding VMAs on such systems.
     */
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!bpf_core_field_exists(mm->mm_rb)) {
        if (!alerted_find_vma_unsupported) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_FIND_VMA_UNSUPPORTED, 0);
            alerted_find_vma_unsupported = true;
        }
        return NULL;
    }

    struct vm_area_struct *vma = NULL;
    struct rb_node *rb_node = BPF_CORE_READ(mm, mm_rb.rb_node);

#pragma unroll
    for (int i = 0; i < MAX_VMA_RB_TREE_DEPTH; i++) {
        barrier(); // without this, the compiler refuses to unroll the loop

        if (rb_node == NULL)
            break;

        struct vm_area_struct *tmp = container_of(rb_node, struct vm_area_struct, vm_rb);
        unsigned long vm_start = BPF_CORE_READ(tmp, vm_start);
        unsigned long vm_end = BPF_CORE_READ(tmp, vm_end);

        if (vm_end > addr) {
            vma = tmp;
            if (vm_start <= addr)
                break;
            rb_node = BPF_CORE_READ(rb_node, rb_left);
        } else
            rb_node = BPF_CORE_READ(rb_node, rb_right);
    }

    return vma;
}

statfunc bool vma_is_stack(struct vm_area_struct *vma)
{
    struct mm_struct *vm_mm = BPF_CORE_READ(vma, vm_mm);
    if (vm_mm == NULL)
        return false;

    u64 vm_start = BPF_CORE_READ(vma, vm_start);
    u64 vm_end = BPF_CORE_READ(vma, vm_end);
    u64 start_stack = BPF_CORE_READ(vm_mm, start_stack);

    // logic taken from include/linux/mm.h (vma_is_initial_stack)
    if (vm_start <= start_stack && start_stack <= vm_end)
        return true;

    return false;
}

statfunc bool vma_is_heap(struct vm_area_struct *vma)
{
    struct mm_struct *vm_mm = BPF_CORE_READ(vma, vm_mm);
    if (vm_mm == NULL)
        return false;

    u64 vm_start = BPF_CORE_READ(vma, vm_start);
    u64 vm_end = BPF_CORE_READ(vma, vm_end);
    u64 start_brk = BPF_CORE_READ(vm_mm, start_brk);
    u64 brk = BPF_CORE_READ(vm_mm, brk);

    // logic taken from include/linux/mm.h (vma_is_initial_heap)
    if (vm_start < brk && start_brk < vm_end)
        return true;

    return false;
}

statfunc bool vma_is_anon(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_file) == NULL;
}

statfunc bool vma_is_vdso(struct vm_area_struct *vma)
{
    struct vm_special_mapping *special_mapping =
        (struct vm_special_mapping *) BPF_CORE_READ(vma, vm_private_data);
    if (special_mapping == NULL)
        return false;

    // read only 6 characters (7 with NULL terminator), enough to compare with "[vdso]"
    char mapping_name[7];
    bpf_probe_read_str(&mapping_name, 7, BPF_CORE_READ(special_mapping, name));
    return strncmp("[vdso]", mapping_name, 7) == 0;
}

statfunc enum vma_type get_vma_type(struct vm_area_struct *vma)
{
    if (vma_is_stack(vma))
        return VMA_STACK;

    if (vma_is_heap(vma))
        return VMA_HEAP;

    if (vma_is_anon(vma) && !vma_is_vdso(vma)) {
        return VMA_ANON;
    }

    return VMA_OTHER;
}

#endif
