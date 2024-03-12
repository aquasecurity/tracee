#ifndef __COMMON_CONTEXT_H__
#define __COMMON_CONTEXT_H__

#include <vmlinux.h>

#include <common/logging.h>
#include <common/task.h>
#include <common/cgroups.h>

// PROTOTYPES

statfunc int init_context(void *, event_context_t *, struct task_struct *, u32);
statfunc int validate_scratch(scratch_t **);
statfunc task_info_t *init_task_info(u32, u32, scratch_t *);
statfunc proc_info_t *init_proc_info_entry(scratch_t *, u32);
statfunc bool context_changed(task_context_t *, task_context_t *);
statfunc int init_program_data(program_data_t *, void *);
statfunc int init_tailcall_program_data(program_data_t *, void *);
statfunc void reset_event_args(program_data_t *);

// FUNCTIONS

statfunc int
init_context(void *ctx, event_context_t *context, struct task_struct *task, u32 options)
{
    long ret = 0;
    u64 id = bpf_get_current_pid_tgid();

    // NOTE: parent is always a real process, not a potential thread group leader
    struct task_struct *leader = get_leader_task(task);
    struct task_struct *up_parent = get_leader_task(get_parent_task(leader));

    // Task Info on Host
    context->task.host_tid = id;
    context->task.host_pid = id >> 32;
    context->task.host_ppid = get_task_pid(up_parent); // always a real process (not a lwp)
    // Namespaces Info
    context->task.tid = get_task_ns_pid(task);
    context->task.pid = get_task_ns_tgid(task);

    u32 task_pidns_id = get_task_pid_ns_id(task);
    u32 up_parent_pidns_id = get_task_pid_ns_id(up_parent);

    if (task_pidns_id == up_parent_pidns_id)
        context->task.ppid = get_task_ns_pid(up_parent); // e.g: pid 1 will have nsppid 0

    context->task.pid_id = task_pidns_id;
    context->task.mnt_id = get_task_mnt_ns_id(task);
    // User Info
    context->task.uid = bpf_get_current_uid_gid();
    // Times
    context->task.start_time = get_task_start_time(task);
    context->task.leader_start_time = get_task_start_time(leader);
    context->task.parent_start_time = get_task_start_time(up_parent);

    context->task.flags = 0;

    if (is_compat(task))
        context->task.flags |= IS_COMPAT_FLAG;

    // Program name
    __builtin_memset(context->task.comm, 0, sizeof(context->task.comm));
    ret = bpf_get_current_comm(&context->task.comm, sizeof(context->task.comm));
    if (unlikely(ret < 0)) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_GET_CURRENT_COMM, ret);
        return -1;
    }

    // UTS Name
    char *uts_name = get_task_uts_name(task);
    if (uts_name) {
        __builtin_memset(context->task.uts_name, 0, sizeof(context->task.uts_name));
        bpf_probe_read_str(&context->task.uts_name, TASK_COMM_LEN, uts_name);
    }

    // Cgroup ID
    if (options & OPT_CGROUP_V1) {
        context->task.cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        context->task.cgroup_id = bpf_get_current_cgroup_id();
    }

    // Context timestamp
    context->ts = bpf_ktime_get_ns();
    // Clean Stack Trace ID
    context->stack_id = 0;
    // Processor ID
    context->processor_id = (u16) bpf_get_smp_processor_id();
    // Syscall ID
    context->syscall = get_task_syscall_id(task);

    return 0;
}

// init_proc_info_entry initializes the proc_info_t entry for the given pid
// into the proc_info_map.
// It returns the pointer to the proc_info_t entry or NULL if the entry
// could not be initialized.
statfunc proc_info_t *init_proc_info_entry(scratch_t *scratch, u32 pid)
{
    if (!validate_scratch(&scratch))
        return NULL;

    proc_info_t *proc_info = &scratch->proc_info;

    // reset scratch proc_info
    __builtin_memset(proc_info, 0, sizeof(proc_info_t));
    bpf_map_update_elem(&proc_info_map, &pid, proc_info, BPF_NOEXIST);
    return bpf_map_lookup_elem(&proc_info_map, &pid);
}

// validate_scratch checks if the scratch pointer is valid and if not, tries to
// retrieve a valid pointer from the scratch_map.
// If successful, it updates the scratch pointer with the valid scratch pointer.
// It returns 1 if the scratch pointer is valid and 0 otherwise.
statfunc int validate_scratch(scratch_t **scratch)
{
    if (scratch == NULL)
        return 0;

    if (*scratch == NULL) {
        u32 zero = 0;
        *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
        if (unlikely(*scratch == NULL))
            return 0;
    }

    return 1;
}

statfunc task_info_t *init_task_info(u32 tid, u32 pid, scratch_t *scratch)
{
    int zero = 0;

    // allow caller to specify a stack/map based scratch_t pointer
    if (!validate_scratch(&scratch))
        return NULL;

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &pid);
    if (proc_info == NULL) {
        proc_info = init_proc_info_entry(scratch, pid);
        if (unlikely(proc_info == NULL))
            return NULL;
    }

    scratch->task_info.syscall_traced = false;
    scratch->task_info.recompute_scope = true;
    scratch->task_info.container_state = CONTAINER_UNKNOWN;
    bpf_map_update_elem(&task_info_map, &tid, &scratch->task_info, BPF_NOEXIST);

    return bpf_map_lookup_elem(&task_info_map, &tid);
}

statfunc bool context_changed(task_context_t *old, task_context_t *new)
{
    return (old->cgroup_id != new->cgroup_id) || old->uid != new->uid ||
           old->mnt_id != new->mnt_id || old->pid_id != new->pid_id ||
           *(u64 *) old->comm != *(u64 *) new->comm ||
           *(u64 *) &old->comm[8] != *(u64 *) &new->comm[8] ||
           *(u64 *) old->uts_name != *(u64 *) new->uts_name ||
           *(u64 *) &old->uts_name[8] != *(u64 *) &new->uts_name[8];
}

// clang-format off
statfunc int init_program_data(program_data_t *p, void *ctx)
{
    long ret = 0;
    int zero = 0;

    // allow caller to specify a stack/map based event_data_t pointer
    if (p->event == NULL) {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->event->task = (struct task_struct *) bpf_get_current_task();
    ret = init_context(ctx, &p->event->context, p->event->task, p->config->options);
    if (unlikely(ret < 0)) {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_INIT_CONTEXT, ret);
        return 0;
    }

    p->ctx = ctx;
    p->event->args_buf.offset = 0;
    p->event->args_buf.argnum = 0;

    bool container_lookup_required = true;

    p->task_info = bpf_map_lookup_elem(&task_info_map, &p->event->context.task.host_tid);
    if (unlikely(p->task_info == NULL)) {
        p->task_info = init_task_info(
            p->event->context.task.host_tid,
            p->event->context.task.host_pid,
            p->scratch
        );
        if (unlikely(p->task_info == NULL)) {
            return 0;
        }
        // just initialized task info: recompute_scope is already set to true
        goto out;
    }

    // in some places we don't call should_trace() (e.g. sys_exit) which also initializes
    // matched_policies. Use previously found scopes then to initialize it.
    p->event->context.matched_policies = p->task_info->matched_scopes;
    p->event->context.policies_version = p->config->policies_version;

    // check if we need to recompute scope due to context change
    if (context_changed(&p->task_info->context, &p->event->context.task))
        p->task_info->recompute_scope = true;

    u8 container_state = p->task_info->container_state;

    // if task is already part of a container: no need to check if state changed
    switch (container_state) {
        case CONTAINER_STARTED:
        case CONTAINER_EXISTED:
            p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
            container_lookup_required = false;
    }

out:
    if (container_lookup_required) {
        u32 cgroup_id_lsb = p->event->context.task.cgroup_id;
        u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);

        if (state != NULL) {
            p->task_info->container_state = *state;
            switch (*state) {
                case CONTAINER_STARTED:
                case CONTAINER_EXISTED:
                    p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
            }
        }
    }

    // update task_info with the new context
    bpf_probe_read(&p->task_info->context, sizeof(task_context_t), &p->event->context.task);

    return 1;
}
// clang-format on

statfunc int init_tailcall_program_data(program_data_t *p, void *ctx)
{
    u32 zero = 0;

    p->ctx = ctx;

    p->event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (unlikely(p->event == NULL))
        return 0;

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->task_info = bpf_map_lookup_elem(&task_info_map, &p->event->context.task.host_tid);
    if (unlikely(p->task_info == NULL)) {
        return 0;
    }

    return 1;
}

// use this function for programs that send more than one event
statfunc void reset_event_args(program_data_t *p)
{
    p->event->args_buf.offset = 0;
    p->event->args_buf.argnum = 0;
}

#endif
