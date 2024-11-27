#ifndef __COMMON_MEMORY_H__
#define __COMMON_MEMORY_H__

#include <vmlinux.h>

#include <common/common.h>

enum vma_type
{
    VMA_FILE_BACKED,
    VMA_ANON,
    VMA_MAIN_STACK,
    VMA_THREAD_STACK,
    VMA_HEAP,
    VMA_GOLANG_HEAP,
    VMA_VDSO,
    VMA_UNKNOWN,
};

// PROTOTYPES

statfunc struct mm_struct *get_mm_from_task(struct task_struct *);
statfunc unsigned long get_arg_start_from_mm(struct mm_struct *);
statfunc unsigned long get_arg_end_from_mm(struct mm_struct *);
statfunc unsigned long get_env_start_from_mm(struct mm_struct *);
statfunc unsigned long get_env_end_from_mm(struct mm_struct *);
statfunc unsigned long get_vma_flags(struct vm_area_struct *);
statfunc struct vm_area_struct *find_vma(void *ctx, struct task_struct *task, u64 addr);
statfunc bool vma_is_file_backed(struct vm_area_struct *vma);
statfunc bool vma_is_main_stack(struct vm_area_struct *vma);
statfunc bool vma_is_main_heap(struct vm_area_struct *vma);
statfunc bool vma_is_anon(struct vm_area_struct *vma);
statfunc bool vma_is_golang_heap(struct vm_area_struct *vma);
statfunc bool vma_is_thread_stack(task_info_t *task_info, struct vm_area_struct *vma);
statfunc bool vma_is_vdso(struct vm_area_struct *vma);
statfunc enum vma_type get_vma_type(task_info_t *task_info, struct vm_area_struct *vma);

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

statfunc bool vma_is_file_backed(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_file) != NULL;
}

statfunc bool vma_is_main_stack(struct vm_area_struct *vma)
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

statfunc bool vma_is_main_heap(struct vm_area_struct *vma)
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
    return !vma_is_file_backed(vma);
}

// The golang heap consists of arenas which are memory regions mapped using mmap.
// When allocating areans, golang supplies mmap with an address hint, which is an
// address that the kernel should place the mapping at.
// Hints are constant and vary between architectures, see `mallocinit()` in
// https://github.com/golang/go/blob/master/src/runtime/malloc.go
// From observation, when allocating arenas the MAP_FIXED flag is used which forces
// the kernel to use the specified address or fail the mapping, so it is safe to
// rely on the address pattern to determine if it belongs to a heap arena.
#define GOLANG_ARENA_HINT_MASK 0x80ff00000000UL
#if defined(bpf_target_x86)
    #define GOLANG_ARENA_HINT (0xc0UL << 32)
#elif defined(bpf_target_arm64)
    #define GOLANG_ARENA_HINT (0x40UL << 32)
#else
    #error Unsupported architecture
#endif

statfunc bool vma_is_golang_heap(struct vm_area_struct *vma)
{
    u64 vm_start = BPF_CORE_READ(vma, vm_start);

    return (vm_start & GOLANG_ARENA_HINT_MASK) == GOLANG_ARENA_HINT;
}

statfunc bool vma_is_thread_stack(task_info_t *task_info, struct vm_area_struct *vma)
{
    // Get the stack area for this task
    address_range_t *stack = &task_info->stack;
    if (stack->start == 0 && stack->end == 0)
        // This thread's stack isn't tracked
        return false;

    // Check if the VMA is **contained** in the thread stack range.
    // We don't check exact address range match because a change to the permissions
    // of part of the stack VMA will split it into multiple VMAs.
    return BPF_CORE_READ(vma, vm_start) >= stack->start && BPF_CORE_READ(vma, vm_end) <= stack->end;
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

statfunc enum vma_type get_vma_type(task_info_t *task_info, struct vm_area_struct *vma)
{
    // The check order is a balance between how expensive the check is and how likely it is to pass

    if (vma_is_file_backed(vma))
        return VMA_FILE_BACKED;

    if (vma_is_main_stack(vma))
        return VMA_MAIN_STACK;

    if (vma_is_main_heap(vma))
        return VMA_HEAP;

    if (vma_is_anon(vma)) {
        if (vma_is_golang_heap(vma))
            return VMA_GOLANG_HEAP;

        if (vma_is_thread_stack(task_info, vma))
            return VMA_THREAD_STACK;

        if (vma_is_vdso(vma))
            return VMA_VDSO;

        return VMA_ANON;
    }

    return VMA_UNKNOWN;
}

statfunc const char *get_vma_type_str(enum vma_type vma_type)
{
    switch (vma_type) {
        case VMA_FILE_BACKED:
            return "file backed";
        case VMA_ANON:
            return "anonymous";
        case VMA_MAIN_STACK:
            return "main stack";
        case VMA_THREAD_STACK:
            return "thread stack";
        case VMA_HEAP:
            return "heap";
        case VMA_GOLANG_HEAP:
            // Goroutine stacks are allocated on the golang heap
            return "golang heap/stack";
        case VMA_VDSO:
            return "vdso";
        case VMA_UNKNOWN:
        default:
            return "unknown";
    }
}

#endif
