#ifndef __COMMON_CONTEXT_H__
#define __COMMON_CONTEXT_H__

#include <vmlinux.h>

#include <common/logging.h>
#include <common/task.h>
#include <common/cgroups.h>
#include <common/common.h>

// PROTOTYPES

statfunc int init_task_context(task_context_t *, struct task_struct *, u32);
statfunc void init_proc_info_scratch(u32, scratch_t *);
statfunc proc_info_t *init_proc_info(u32, u32);
statfunc void init_task_info_scratch(u32, scratch_t *);
statfunc task_info_t *init_task_info(u32, u32);
statfunc event_config_t *get_event_config(u32, u16);
statfunc int init_program_data(program_data_t *, void *, u32);
statfunc int init_tailcall_program_data(program_data_t *, void *);
statfunc bool reset_event(event_data_t *, u32);
statfunc void reset_event_args_buf(event_data_t *);
statfunc bool thread_stack_tracked(task_info_t *);

// FUNCTIONS

statfunc int init_task_context(task_context_t *tsk_ctx, struct task_struct *task, u32 options)
{
    // NOTE: parent process is always a real process, not a potential thread group leader
    struct task_struct *leader = get_leader_task(task);
    struct task_struct *parent_process = get_leader_task(get_parent_task(leader));

    // Task Info on Host
    tsk_ctx->host_ppid = get_task_pid(parent_process); // always a real process (not a lwp)
    // Namespaces Info
    tsk_ctx->tid = get_task_ns_pid(task);
    tsk_ctx->pid = get_task_ns_tgid(task);

    u32 task_pidns_id = get_task_pid_ns_id(task);
    u32 parent_process_pidns_id = get_task_pid_ns_id(parent_process);

    if (task_pidns_id == parent_process_pidns_id)
        tsk_ctx->ppid = get_task_ns_pid(parent_process); // e.g: pid 1 will have nsppid 0

    tsk_ctx->pid_id = task_pidns_id;
    tsk_ctx->mnt_id = get_task_mnt_ns_id(task);
    // User Info
    tsk_ctx->uid = bpf_get_current_uid_gid();
    // Times
    tsk_ctx->start_time = get_task_start_time(task);
    tsk_ctx->leader_start_time = get_task_start_time(leader);
    tsk_ctx->parent_start_time = get_task_start_time(parent_process);

    if (is_compat(task))
        tsk_ctx->flags |= IS_COMPAT_FLAG;

    // Program name
    bpf_get_current_comm(&tsk_ctx->comm, sizeof(tsk_ctx->comm));

    // UTS Name
    char *uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_kernel_str(&tsk_ctx->uts_name, TASK_COMM_LEN, uts_name);

    return 0;
}

statfunc void init_proc_info_scratch(u32 pid, scratch_t *scratch)
{
    __builtin_memset(&scratch->proc_info, 0, sizeof(proc_info_t));
    bpf_map_update_elem(&proc_info_map, &pid, &scratch->proc_info, BPF_NOEXIST);
}

statfunc proc_info_t *init_proc_info(u32 pid, u32 scratch_idx)
{
    scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_idx);
    if (unlikely(scratch == NULL))
        return NULL;

    init_proc_info_scratch(pid, scratch);

    return bpf_map_lookup_elem(&proc_info_map, &pid);
}

statfunc void init_task_info_scratch(u32 tid, scratch_t *scratch)
{
    __builtin_memset(&scratch->task_info, 0, sizeof(task_info_t));
    bpf_map_update_elem(&task_info_map, &tid, &scratch->task_info, BPF_NOEXIST);
}

statfunc task_info_t *init_task_info(u32 tid, u32 scratch_idx)
{
    scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_idx);
    if (unlikely(scratch == NULL))
        return NULL;

    init_task_info_scratch(tid, scratch);

    return bpf_map_lookup_elem(&task_info_map, &tid);
}

statfunc event_config_t *get_event_config(u32 event_id, u16 policies_version)
{
    // TODO: we can remove this extra lookup by moving to per event rules_version
    void *inner_events_map = bpf_map_lookup_elem(&events_map_version, &policies_version);
    if (inner_events_map == NULL)
        return NULL;

    return bpf_map_lookup_elem(inner_events_map, &event_id);
}

// clang-format off
statfunc int init_program_data(program_data_t *p, void *ctx, u32 event_id)
{
    int zero = 0;

    p->ctx = ctx;

    // allow caller to specify a stack/map based event_data_t pointer
    if (p->event == NULL) {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    reset_event_args_buf(p->event);

    p->event->task = (struct task_struct *) bpf_get_current_task();

    __builtin_memset(&p->event->context.task, 0, sizeof(p->event->context.task));

    // get the minimal context required at this stage
    // any other context will be initialized only if event is submitted
    u64 id = bpf_get_current_pid_tgid();
    p->event->context.task.host_tid = id;
    p->event->context.task.host_pid = id >> 32;
    p->event->context.eventid = event_id;
    p->event->context.ts = get_current_time_in_ns();
    p->event->context.processor_id = (u16) bpf_get_smp_processor_id();
    p->event->context.syscall = get_current_task_syscall_id();

    u32 host_pid = p->event->context.task.host_pid;
    p->proc_info = bpf_map_lookup_elem(&proc_info_map, &host_pid);
    if (unlikely(p->proc_info == NULL)) {
        p->proc_info = init_proc_info(host_pid, p->scratch_idx);
        if (unlikely(p->proc_info == NULL))
            return 0;
    }

    u32 host_tid = p->event->context.task.host_tid;
    p->task_info = bpf_map_lookup_elem(&task_info_map, &host_tid);
    if (unlikely(p->task_info == NULL)) {
        p->task_info = init_task_info(host_tid, p->scratch_idx);
        if (unlikely(p->task_info == NULL))
            return 0;

        init_task_context(&p->task_info->context, p->event->task, p->config->options);
    }

    if (p->config->options & OPT_CGROUP_V1) {
        p->event->context.task.cgroup_id = get_cgroup_v1_subsys0_id(p->event->task);
    } else {
        p->event->context.task.cgroup_id = bpf_get_current_cgroup_id();
    }
    p->task_info->context.cgroup_id = p->event->context.task.cgroup_id;
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

    if (unlikely(p->event->context.policies_version != p->config->policies_version)) {
        // copy policies_config to event data
        long ret = bpf_probe_read_kernel(
            &p->event->policies_config, sizeof(policies_config_t), &p->config->policies_config);
        if (unlikely(ret != 0))
            return 0;

        p->event->context.policies_version = p->config->policies_version;
    }

    // default to match all policies until an event is selected
    p->event->config.submit_for_policies = ~0ULL;

    if (event_id != NO_EVENT_SUBMIT) {
        p->event->config.submit_for_policies = 0;
        event_config_t *event_config = get_event_config(event_id, p->event->context.policies_version);
        if (event_config != NULL) {
            p->event->config.field_types = event_config->field_types;
            p->event->config.submit_for_policies = event_config->submit_for_policies;
            p->event->config.data_filter = event_config->data_filter;
        }
    }

    // initialize matched_policies to the policies that actually requested this event
    p->event->context.matched_policies = p->event->config.submit_for_policies;

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

    p->proc_info = bpf_map_lookup_elem(&proc_info_map, &p->event->context.task.host_pid);
    if (unlikely(p->proc_info == NULL)) {
        return 0;
    }

    return 1;
}

// use this function in programs that send the same event more than once
statfunc void reset_event_args_buf(event_data_t *event)
{
    event->args_buf.offset = 0;
    event->args_buf.argnum = 0;

    // Mark all entries in args_offset as invalid (0xFF)
    __builtin_memset(event->args_buf.args_offset, 0xFF, sizeof(event->args_buf.args_offset));
}

// use this function in programs that send more than one event
statfunc bool reset_event(event_data_t *event, u32 event_id)
{
    event->context.eventid = event_id;
    reset_event_args_buf(event);
    event->config.submit_for_policies = ~0ULL;

    event_config_t *event_config = get_event_config(event_id, event->context.policies_version);
    if (event_config == NULL)
        return false;

    event->config.field_types = event_config->field_types;
    event->config.submit_for_policies = event_config->submit_for_policies;
    event->context.matched_policies = event_config->submit_for_policies;

    return true;
}

statfunc bool thread_stack_tracked(task_info_t *task_info)
{
    return task_info->stack.start != 0 && task_info->stack.end != 0;
}

#endif
