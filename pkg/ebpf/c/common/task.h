#ifndef __COMMON_TASK_H__
#define __COMMON_TASK_H__

#include <vmlinux.h>
#include <vmlinux_flavors.h>

#include <common/arch.h>
#include <common/namespaces.h>

// PROTOTYPES

statfunc int get_task_flags(struct task_struct *task);
statfunc int get_task_syscall_id(struct task_struct *task);
statfunc u32 get_task_mnt_ns_id(struct task_struct *task);
statfunc u32 get_task_pid_ns_for_children_id(struct task_struct *task);
statfunc u32 get_task_pid_ns_id(struct task_struct *task);
statfunc u32 get_task_uts_ns_id(struct task_struct *task);
statfunc u32 get_task_ipc_ns_id(struct task_struct *task);
statfunc u32 get_task_net_ns_id(struct task_struct *task);
statfunc u32 get_task_cgroup_ns_id(struct task_struct *task);
statfunc u32 get_task_pid_vnr(struct task_struct *task);
statfunc u32 get_task_ns_pid(struct task_struct *task);
statfunc u32 get_task_ns_tgid(struct task_struct *task);
statfunc u32 get_task_ns_ppid(struct task_struct *task);
statfunc char *get_task_uts_name(struct task_struct *task);
statfunc u32 get_task_ppid(struct task_struct *task);
statfunc u64 get_task_start_time(struct task_struct *task);
statfunc u32 get_task_host_pid(struct task_struct *task);
statfunc u32 get_task_host_tgid(struct task_struct *task);
statfunc struct task_struct *get_parent_task(struct task_struct *task);
statfunc u32 get_task_exit_code(struct task_struct *task);
statfunc int get_task_parent_flags(struct task_struct *task);
statfunc const struct cred *get_task_real_cred(struct task_struct *task);

// FUNCTIONS

statfunc int get_task_flags(struct task_struct *task)
{
    return BPF_CORE_READ(task, flags);
}

statfunc int get_task_syscall_id(struct task_struct *task)
{
    // There is no originated syscall in kernel thread context
    if (get_task_flags(task) & PF_KTHREAD) {
        return NO_SYSCALL;
    }
    struct pt_regs *regs = get_task_pt_regs(task);
    return get_syscall_id_from_regs(regs);
}

statfunc u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_pid_ns_for_children_id(struct task_struct *task)
{
    return get_pid_ns_for_children_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_pid_ns_id(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    struct pid_namespace *ns = NULL;

    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = BPF_CORE_READ(t, pids[PIDTYPE_PID].pid);
    } else {
        pid = BPF_CORE_READ(task, thread_pid);
    }

    level = BPF_CORE_READ(pid, level);
    ns = BPF_CORE_READ(pid, numbers[level].ns);
    return BPF_CORE_READ(ns, ns.inum);
}

statfunc u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_ipc_ns_id(struct task_struct *task)
{
    return get_ipc_ns_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_net_ns_id(struct task_struct *task)
{
    return get_net_ns_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_cgroup_ns_id(struct task_struct *task)
{
    return get_cgroup_ns_id(BPF_CORE_READ(task, nsproxy));
}

statfunc u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = BPF_CORE_READ(t, pids[PIDTYPE_PID].pid);
    } else {
        pid = BPF_CORE_READ(task, thread_pid);
    }

    level = BPF_CORE_READ(pid, level);

    return BPF_CORE_READ(pid, numbers[level].nr);
}

statfunc u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

statfunc u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    return get_task_pid_vnr(group_leader);
}

statfunc u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    return get_task_pid_vnr(real_parent);
}

statfunc char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = BPF_CORE_READ(task, nsproxy);
    struct uts_namespace *uts_ns = BPF_CORE_READ(np, uts_ns);
    return BPF_CORE_READ(uts_ns, name.nodename);
}

statfunc u32 get_task_pid(struct task_struct *task)
{
    return BPF_CORE_READ(task, pid);
}

statfunc u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

statfunc u64 get_task_start_time(struct task_struct *task)
{
    return BPF_CORE_READ(task, start_time);
}

statfunc u32 get_task_host_pid(struct task_struct *task)
{
    return BPF_CORE_READ(task, pid);
}

statfunc u32 get_task_host_tgid(struct task_struct *task)
{
    return BPF_CORE_READ(task, tgid);
}

statfunc struct task_struct *get_parent_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, real_parent);
}

statfunc struct task_struct *get_leader_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, group_leader);
}

statfunc u32 get_task_exit_code(struct task_struct *task)
{
    return BPF_CORE_READ(task, exit_code);
}

statfunc int get_task_parent_flags(struct task_struct *task)
{
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return get_task_flags(parent);
}

statfunc const struct cred *get_task_real_cred(struct task_struct *task)
{
    return BPF_CORE_READ(task, real_cred);
}

#endif
