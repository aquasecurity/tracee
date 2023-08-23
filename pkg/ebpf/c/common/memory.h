#ifndef __COMMON_MEMORY_H__
#define __COMMON_MEMORY_H__

#include <vmlinux.h>

#include <common/common.h>
#include <common/ksymbols.h>

// PROTOTYPES

statfunc struct mm_struct *get_mm_from_task(struct task_struct *);
statfunc unsigned long get_arg_start_from_mm(struct mm_struct *);
statfunc unsigned long get_arg_end_from_mm(struct mm_struct *);
statfunc unsigned long get_env_start_from_mm(struct mm_struct *);
statfunc unsigned long get_env_end_from_mm(struct mm_struct *);
statfunc struct task_struct *get_owner_task_from_mm(struct mm_struct *);
statfunc unsigned long get_vma_flags(struct vm_area_struct *);
statfunc int get_vma_location(struct vm_area_struct *, size_t, char *);

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

statfunc struct task_struct *get_owner_task_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, owner);
}

statfunc struct file *get_mapped_file_from_vma(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_file);
}

statfunc unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_flags);
}

// The function uses the "special_mapping_vmops" and "legacy_special_mapping_vmops" symbols, so
// they should be requested by the event using this function.
statfunc bool is_special_mapping(struct vm_area_struct *vma)
{
    char special_mapping_vmops_symbol[22] = "special_mapping_vmops";
    void *special_mapping_vmops_addr = get_symbol_addr(special_mapping_vmops_symbol);
    char legacy_special_mapping_vmops_symbol[29] = "legacy_special_mapping_vmops";
    void *legacy_special_mapping_vmops_addr = get_symbol_addr(legacy_special_mapping_vmops_symbol);
    const struct vm_operations_struct *vm_ops = BPF_CORE_READ(vma, vm_ops);
    if (vm_ops != NULL &&
        (vm_ops == special_mapping_vmops_addr || vm_ops == legacy_special_mapping_vmops_addr)) {
        return true;
    }
    return false;
}

// Return the name of the location related to the given vma. For example [stack], [heap] and [vdso].
// This function doesn't resolve file mapped vmas, so if the vma is a memory mapped file its
// details should be collected in a different way.
// The function uses the "special_mapping_vmops" and "legacy_special_mapping_vmops" symbols, so
// they should be requested by the event using this function.
statfunc int get_vma_location(struct vm_area_struct *vma, size_t max_len, char *location)
{
    // Avoid buffer overflow and satisfy the verifier.
    if (max_len < 7) {
        return 0;
    }
    struct mm_struct *vm_mm = BPF_CORE_READ(vma, vm_mm);
    if (vm_mm) {
        unsigned long start_stack = BPF_CORE_READ(vm_mm, start_stack);
        unsigned long start_brk = BPF_CORE_READ(vm_mm, start_brk);
        unsigned long brk = BPF_CORE_READ(vm_mm, brk);
        u64 vm_start = BPF_CORE_READ(vma, vm_start);
        u64 vm_end = BPF_CORE_READ(vma, vm_end);

        if (vm_start <= start_stack && vm_end >= start_stack) {
            __builtin_memcpy(location, "[stack]", 7);
        } else if (vm_start <= brk && vm_end >= start_brk) {
            __builtin_memcpy(location, "[heap]", 6);
        } else if (is_special_mapping(vma)) {
            struct vm_special_mapping *special_mapping = BPF_CORE_READ(vma, vm_private_data);
            const char *name = BPF_CORE_READ(special_mapping, name);
            if (name) {
                bpf_probe_read_str(location, max_len, name);
            }
        }
    }
    return 0;
}

statfunc struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

#endif
