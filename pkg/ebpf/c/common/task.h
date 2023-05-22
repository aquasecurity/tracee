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
    return READ_KERN(task->flags);
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
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

statfunc u32 get_task_pid_ns_for_children_id(struct task_struct *task)
{
    return get_pid_ns_for_children_id(READ_KERN(task->nsproxy));
}

statfunc u32 get_task_pid_ns_id(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    struct pid_namespace *ns = NULL;

    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = READ_KERN(t->pids[PIDTYPE_PID].pid);
    } else {
        pid = READ_KERN(task->thread_pid);
    }

    level = READ_KERN(pid->level);
    ns = READ_KERN(pid->numbers[level].ns);
    return READ_KERN(ns->ns.inum);
}

statfunc u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(READ_KERN(task->nsproxy));
}

statfunc u32 get_task_ipc_ns_id(struct task_struct *task)
{
    return get_ipc_ns_id(READ_KERN(task->nsproxy));
}

statfunc u32 get_task_net_ns_id(struct task_struct *task)
{
    return get_net_ns_id(READ_KERN(task->nsproxy));
}

statfunc u32 get_task_cgroup_ns_id(struct task_struct *task)
{
    return get_cgroup_ns_id(READ_KERN(task->nsproxy));
}

statfunc u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = READ_KERN(t->pids[PIDTYPE_PID].pid);
    } else {
        pid = READ_KERN(task->thread_pid);
    }

    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}

statfunc u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

statfunc u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}

statfunc u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    return get_task_pid_vnr(real_parent);
}

statfunc char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}

statfunc u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->tgid);
}

statfunc u64 get_task_start_time(struct task_struct *task)
{
    return READ_KERN(task->start_time);
}

statfunc u32 get_task_host_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

statfunc u32 get_task_host_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

statfunc struct task_struct *get_parent_task(struct task_struct *task)
{
    return READ_KERN(task->real_parent);
}

statfunc u32 get_task_exit_code(struct task_struct *task)
{
    return READ_KERN(task->exit_code);
}

statfunc int get_task_parent_flags(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return get_task_flags(parent);
}

statfunc const struct cred *get_task_real_cred(struct task_struct *task)
{
    return READ_KERN(task->real_cred);
}

#endif
