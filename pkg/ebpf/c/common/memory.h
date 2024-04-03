#ifndef __COMMON_MEMORY_H__
#define __COMMON_MEMORY_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

typedef long (*vma_callback_fn)(struct task_struct *task,
                                struct vm_area_struct *vma,
                                void *callback_ctx);

statfunc struct mm_struct *get_mm_from_task(struct task_struct *);
statfunc unsigned long get_arg_start_from_mm(struct mm_struct *);
statfunc unsigned long get_arg_end_from_mm(struct mm_struct *);
statfunc unsigned long get_env_start_from_mm(struct mm_struct *);
statfunc unsigned long get_env_end_from_mm(struct mm_struct *);
statfunc unsigned long get_vma_flags(struct vm_area_struct *);
statfunc unsigned long get_vma_start(struct vm_area_struct *);
statfunc void find_vma(struct task_struct *task, u64 addr, vma_callback_fn cb_fn, void *cb_ctx);
statfunc bool vma_is_stack(struct vm_area_struct *vma);
statfunc bool vma_is_heap(struct vm_area_struct *vma);

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

statfunc unsigned long get_vma_start(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_start);
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

/**
 * Given a task, find the first VMA which contains the given address,
 * and call the specified callback function with the found VMA
 * and the specified context.
 * A callback function is required becuase this function potentially uses
 * bpf_find_vma(), which requires a callback function.
 *
 * A generic callback function which receives a `struct vm_area_struct **`
 * as its context and saves the found VMA to it is available in the main
 * eBPF source file (tracee.bpf.c:find_vma_callback).
 *
 * See the check_syscall_source function for a usage example.
 *
 * DISCLAIMER: on systems with no MMU, multiple VMAs may contain the same address.
 * Be aware that this function will call the callback only for the first VMA it finds.
 */
statfunc void find_vma(struct task_struct *task, u64 addr, vma_callback_fn cb_fn, void *cb_ctx)
{
    /**
     * From kernel version 6.1, the data structure with which VMAs
     * are managed changed from an RB tree to a maple tree.
     * In version 5.17 the "bpf_find_vma" helper was added.
     * This means that if the helper does not exist, we can assume
     * that the RB tree structure is used.
     */

    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_find_vma)) {
        bpf_find_vma(task, addr, cb_fn, cb_ctx, 0);
        return;
    }

    // bpf_find_vma doesn't exist, we can assume the VMAs are stored in an RB tree.
    // This logic is based on the find_vma() function in mm/mmap.c

    struct vm_area_struct *vma = NULL;
    struct rb_node *rb_node = BPF_CORE_READ(task, mm->mm_rb.rb_node);

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

    if (vma != NULL)
        cb_fn(task, vma, cb_ctx);
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

#endif
