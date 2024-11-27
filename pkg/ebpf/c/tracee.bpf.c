// +build ignore

// Note: This file is licenced differently from the rest of the project
// SPDX-License-Identifier: GPL-2.0
// Copyright (C) Aqua Security inc.

#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#undef container_of

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <maps.h>
#include <types.h>
#include <capture_filtering.h>
#include <tracee.h>

#include <common/arch.h>
#include <common/arguments.h>
#include <common/binprm.h>
#include <common/bpf_prog.h>
#include <common/buffer.h>
#include <common/capabilities.h>
#include <common/cgroups.h>
#include <common/common.h>
#include <common/consts.h>
#include <common/context.h>
#include <common/filesystem.h>
#include <common/filtering.h>
#include <common/kconfig.h>
#include <common/ksymbols.h>
#include <common/logging.h>
#include <common/memory.h>
#include <common/network.h>
#include <common/probes.h>
#include <common/signal.h>

char LICENSE[] SEC("license") = "GPL";

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
// initial entry for sys_enter syscall logic
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    int id = ctx->args[1];
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    bpf_tail_call(ctx, &sys_enter_init_tail, id);
    return 0;
}

// initial tail call entry from sys_enter.
// purpose is to save the syscall info of relevant syscalls through the task_info map.
// can move to one of:
// 1. sys_enter_submit, general event submit logic from sys_enter
// 2. directly to syscall tail hanler in sys_enter_tails
SEC("raw_tracepoint/sys_enter_init")
int sys_enter_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        task_info = init_task_info(tid, 0);
        if (unlikely(task_info == NULL))
            return 0;

        int zero = 0;
        config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
        if (unlikely(config == NULL))
            return 0;

        init_task_context(&task_info->context, task, config->options);
    }

    syscall_data_t *sys = &(task_info->syscall_data);
    sys->id = ctx->args[1];

    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

    if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
        sys->args.args[0] = BPF_CORE_READ(regs, bx);
        sys->args.args[1] = BPF_CORE_READ(regs, cx);
        sys->args.args[2] = BPF_CORE_READ(regs, dx);
        sys->args.args[3] = BPF_CORE_READ(regs, si);
        sys->args.args[4] = BPF_CORE_READ(regs, di);
        sys->args.args[5] = BPF_CORE_READ(regs, bp);
#endif // bpf_target_x86
    } else {
        sys->args.args[0] = PT_REGS_PARM1_CORE_SYSCALL(regs);
        sys->args.args[1] = PT_REGS_PARM2_CORE_SYSCALL(regs);
        sys->args.args[2] = PT_REGS_PARM3_CORE_SYSCALL(regs);
        sys->args.args[3] = PT_REGS_PARM4_CORE_SYSCALL(regs);
        sys->args.args[4] = PT_REGS_PARM5_CORE_SYSCALL(regs);
        sys->args.args[5] = PT_REGS_PARM6_CORE_SYSCALL(regs);
    }

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys->id);
        if (id_64 == 0)
            return 0;

        sys->id = *id_64;
    }

    // exit, exit_group and rt_sigreturn syscalls don't return
    if (sys->id != SYSCALL_EXIT && sys->id != SYSCALL_EXIT_GROUP &&
        sys->id != SYSCALL_RT_SIGRETURN) {
        sys->ts = get_current_time_in_ns();
        task_info->syscall_traced = true;
    }

    // if id is irrelevant continue to next tail call
    bpf_tail_call(ctx, &sys_enter_submit_tail, sys->id);

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// submit tail call part of sys_enter.
// events that are required for submission go through two logics here:
// 1. parsing their FD filepath if requested as an option
// 2. submitting the event if relevant
// may move to the direct syscall handler in sys_enter_tails
SEC("raw_tracepoint/sys_enter_submit")
int sys_enter_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (!reset_event(p.event, sys->id))
        return 0;

    if (!evaluate_scope_filters(&p))
        goto out;

    if (p.config->options & OPT_TRANSLATE_FD_FILEPATH && has_syscall_fd_arg(sys->id)) {
        // Process filepath related to fd argument
        uint fd_num = get_syscall_fd_num_from_arg(sys->id, &sys->args);
        struct file *f = get_struct_file_from_fd(fd_num);

        if (f) {
            u64 ts = sys->ts;
            fd_arg_path_t fd_arg_path = {};
            void *file_path = get_path_str(__builtin_preserve_access_index(&f->f_path));

            bpf_probe_read_kernel_str(&fd_arg_path.path, sizeof(fd_arg_path.path), file_path);
            bpf_map_update_elem(&fd_arg_path_map, &ts, &fd_arg_path, BPF_ANY);
        }
    }

    if (sys->id != SYSCALL_RT_SIGRETURN && !p.task_info->syscall_traced) {
        save_to_submit_buf(&p.event->args_buf, (void *) &(sys->args.args[0]), sizeof(int), 0);
        events_perf_submit(&p, 0);
    }

out:
    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long ret)
// initial entry for sys_exit syscall logic
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    bpf_tail_call(ctx, &sys_exit_init_tail, id);
    return 0;
}

// initial tail call entry from sys_exit.
// purpose is to "confirm" the syscall data saved by marking it as complete(see
// task_info->syscall_traced) and adding the return value to the syscall_info struct. can move to
// one of:
// 1. sys_exit, general event submit logic from sys_exit
// 2. directly to syscall tail hanler in sys_exit_tails
SEC("raw_tracepoint/sys_exit_init")
int sys_exit_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        task_info = init_task_info(tid, 0);
        if (unlikely(task_info == NULL))
            return 0;

        int zero = 0;
        config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
        if (unlikely(config == NULL))
            return 0;

        init_task_context(&task_info->context, task, config->options);
    }

    // check if syscall is being traced and mark that it finished
    if (!task_info->syscall_traced)
        return 0;
    task_info->syscall_traced = false;

    syscall_data_t *sys = &task_info->syscall_data;

    long ret = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // Sanity check - we returned from the expected syscall this task was executing
    if (sys->id != id)
        return 0;

    sys->ret = ret;

    // move to submit tail call if needed
    bpf_tail_call(ctx, &sys_exit_submit_tail, id);

    // otherwise move to direct syscall handler
    bpf_tail_call(ctx, &sys_exit_tails, id);
    return 0;
}

// submit tail call part of sys_exit.
// most syscall events are submitted at this point, and if not,
// they are submitted through direct syscall handlers in sys_exit_tails
SEC("raw_tracepoint/sys_exit_submit")
int sys_exit_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (!reset_event(p.event, sys->id))
        return 0;

    long ret = ctx->args[1];

    if (!evaluate_scope_filters(&p))
        goto out;

    // exec syscalls are different since the pointers are invalid after a successful exec.
    // we use a special handler (tail called) to only handle failed execs on syscall exit.
    if (sys->id == SYSCALL_EXECVE || sys->id == SYSCALL_EXECVEAT)
        goto out;

    save_args_to_submit_buf(p.event, &sys->args);
    p.event->context.ts = sys->ts;
    events_perf_submit(&p, ret);

out:
    bpf_tail_call(ctx, &sys_exit_tails, sys->id);
    return 0;
}

// here are the direct hook points for sys_enter and sys_exit.
// There are used not for submitting syscall events but the enter and exit events themselves.
// As such they are usually not attached, and will only be used if sys_enter or sys_exit events are
// given as tracing arguments.

// separate hook point for sys_enter event tracing
SEC("raw_tracepoint/trace_sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, RAW_SYS_ENTER))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // always submit since this won't be attached otherwise
    int id = ctx->args[1];
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &id, sizeof(int), 0);
    events_perf_submit(&p, 0);
    return 0;
}

// separate hook point for sys_exit event tracing
SEC("raw_tracepoint/trace_sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, RAW_SYS_EXIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // always submit since this won't be attached otherwise
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &id, sizeof(int), 0);
    events_perf_submit(&p, 0);
    return 0;
}

// macros for syscall kprobes
TRACE_SYSCALL(ptrace, SYSCALL_PTRACE)
TRACE_SYSCALL(process_vm_writev, SYSCALL_PROCESS_VM_WRITEV)
TRACE_SYSCALL(arch_prctl, SYSCALL_ARCH_PRCTL)
TRACE_SYSCALL(dup, SYSCALL_DUP)
TRACE_SYSCALL(dup2, SYSCALL_DUP2)
TRACE_SYSCALL(dup3, SYSCALL_DUP3)

SEC("raw_tracepoint/sys_execve")
int syscall__execve_enter(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;
    p.event->context.ts = sys->ts;

    if (!reset_event(p.event, SYSCALL_EXECVE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    save_str_to_buf(&p.event->args_buf, (void *) sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) sys->args.args[1] /*argv*/, 1);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(
            &p.event->args_buf, (const char *const *) sys->args.args[2] /*envp*/, 2);
    }

    return events_perf_submit(&p, 0);
}

SEC("raw_tracepoint/sys_execve")
int syscall__execve_exit(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    // To avoid showing execve event both on entry and exit, we only output failed execs.
    if (!sys->ret)
        return -1;

    p.event->context.ts = sys->ts;

    if (!reset_event(p.event, SYSCALL_EXECVE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    save_str_to_buf(&p.event->args_buf, (void *) sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) sys->args.args[1] /*argv*/, 1);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(
            &p.event->args_buf, (const char *const *) sys->args.args[2] /*envp*/, 2);
    }

    return events_perf_submit(&p, sys->ret);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat_enter(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;
    p.event->context.ts = sys->ts;

    if (!reset_event(p.event, SYSCALL_EXECVEAT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(&p.event->args_buf, (void *) sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) sys->args.args[2] /*argv*/, 2);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(
            &p.event->args_buf, (const char *const *) sys->args.args[3] /*envp*/, 3);
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_perf_submit(&p, 0);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat_exit(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    // To avoid showing execve event both on entry and exit, we only output failed execs.
    if (!sys->ret)
        return -1;

    p.event->context.ts = sys->ts;

    if (!reset_event(p.event, SYSCALL_EXECVEAT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(&p.event->args_buf, (void *) sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) sys->args.args[2] /*argv*/, 2);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(
            &p.event->args_buf, (const char *const *) sys->args.args[3] /*envp*/, 3);
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_perf_submit(&p, sys->ret);
}

statfunc int send_socket_dup(program_data_t *p, u64 oldfd, u64 newfd)
{
    if (!check_fd_type(oldfd, S_IFSOCK))
        return 0;

    struct file *f = get_struct_file_from_fd(oldfd);
    if (f == NULL)
        return -1;

    // this is a socket - submit the SOCKET_DUP event

    save_to_submit_buf(&(p->event->args_buf), &oldfd, sizeof(u32), 0);
    save_to_submit_buf(&(p->event->args_buf), &newfd, sizeof(u32), 1);

    // get the address
    struct socket *socket_from_file = (struct socket *) BPF_CORE_READ(f, private_data);
    if (socket_from_file == NULL)
        return -1;

    struct sock *sk = get_socket_sock(socket_from_file);
    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX))
        return 0;

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in remote;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(
            &(p->event->args_buf), &remote, bpf_core_type_size(struct sockaddr_in), 2);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 remote;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(
            &(p->event->args_buf), &remote, bpf_core_type_size(struct sockaddr_in6), 2);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);

        save_to_submit_buf(
            &(p->event->args_buf), &sockaddr, bpf_core_type_size(struct sockaddr_un), 2);
    }

    return events_perf_submit(p, 0);
}

SEC("kprobe/sys_dup")
int sys_dup_exit_tail(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (sys->ret < 0) {
        // dup failed
        return 0;
    }

    if (!reset_event(p.event, SOCKET_DUP))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    if (sys->id == SYSCALL_DUP) {
        // args.args[0]: oldfd
        // retval: newfd
        send_socket_dup(&p, sys->args.args[0], sys->ret);
    } else if (sys->id == SYSCALL_DUP2 || sys->id == SYSCALL_DUP3) {
        // args.args[0]: oldfd
        // args.args[1]: newfd
        // retval: retval
        send_socket_dup(&p, sys->args.args[0], sys->args.args[1]);
    }

    return 0;
}

statfunc void update_thread_stack(void *ctx, task_info_t *task_info, struct task_struct *task)
{
    // Kernel threads and group leaders are not relevant, reset their stack area
    if (get_task_flags(task) & PF_KTHREAD || BPF_CORE_READ(task, pid) == BPF_CORE_READ(task, tgid))
        task_info->stack = (address_range_t){0};

        // Get user SP of new thread
#if defined(bpf_target_x86)
    struct fork_frame *fork_frame = (struct fork_frame *) BPF_CORE_READ(task, thread.sp);
    u64 thread_sp = BPF_CORE_READ(fork_frame, regs.sp);
#elif defined(bpf_target_arm64)
    struct pt_regs *thread_regs = (struct pt_regs *) BPF_CORE_READ(task, thread.cpu_context.sp);
    u64 thread_sp = BPF_CORE_READ(thread_regs, sp);
#else
    #error Unsupported architecture
#endif

    // Find VMA which contains the SP
    struct vm_area_struct *vma = find_vma(ctx, task, thread_sp);
    if (unlikely(vma == NULL))
        return;

    // Add the VMA address range to the task info
    task_info->stack =
        (address_range_t){.start = BPF_CORE_READ(vma, vm_start), .end = BPF_CORE_READ(vma, vm_end)};
}

// trace/events/sched.h: TP_PROTO(struct task_struct *parent, struct task_struct *child)
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SCHED_PROCESS_FORK))
        return 0;

    // NOTE: update proc_info_map before evaluate_scope_filters() as the entries are needed in other
    // places.

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    // Information needed before the event:
    int parent_pid = get_task_host_tgid(parent);
    u64 child_start_time = get_task_start_time(child);
    int child_pid = get_task_host_tgid(child);
    int child_tid = get_task_host_pid(child);
    int child_ns_pid = get_task_ns_tgid(child);
    int child_ns_tid = get_task_ns_pid(child);

    // Update the task_info map with the new task's info

    ret = bpf_map_update_elem(&task_info_map, &child_tid, p.task_info, BPF_ANY);
    if (ret < 0)
        tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);
    task_info_t *task = bpf_map_lookup_elem(&task_info_map, &child_tid);
    if (unlikely(task == NULL)) {
        // this should never happen - we just updated the map with this key
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    task->context.tid = child_ns_tid;
    task->context.host_tid = child_tid;
    task->context.start_time = child_start_time;

    // Track thread stack if needed
    if (event_is_selected(SUSPICIOUS_SYSCALL_SOURCE, p.event->context.policies_version) ||
        event_is_selected(STACK_PIVOT, p.event->context.policies_version))
        update_thread_stack(ctx, task, child);

    // Update the proc_info_map with the new process's info (from parent)

    proc_info_t *c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_pid);
    if (c_proc_info == NULL) {
        // It is a new process (not another thread): add it to proc_info_map.
        proc_info_t *p_proc_info = bpf_map_lookup_elem(&proc_info_map, &parent_pid);
        if (unlikely(p_proc_info == NULL)) {
            // parent should exist in proc_info_map (init_program_data sets it)
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        // Copy the parent's proc_info to the child's entry.
        bpf_map_update_elem(&proc_info_map, &child_pid, p_proc_info, BPF_NOEXIST);
        c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_pid);
        if (unlikely(c_proc_info == NULL)) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        c_proc_info->follow_in_scopes = get_scopes_to_follow(&p); // follow task for matched scopes
        c_proc_info->new_proc = true; // started after tracee (new_pid filter)
    }

    // Update the process tree map (filter related) if the parent has an entry.

    policies_config_t *policies_cfg = &p.event->policies_config;

    if (policies_cfg->proc_tree_filter_enabled) {
        u16 version = p.event->context.policies_version;
        // Give the compiler a hint about the map type, otherwise libbpf will complain
        // about missing type information. i.e.: "can't determine value size for type".
        process_tree_map_t *inner_proc_tree_map = &process_tree_map;

        inner_proc_tree_map = bpf_map_lookup_elem(&process_tree_map_version, &version);
        if (inner_proc_tree_map != NULL) {
            eq_t *tgid_filtered = bpf_map_lookup_elem(inner_proc_tree_map, &parent_pid);
            if (tgid_filtered) {
                ret = bpf_map_update_elem(inner_proc_tree_map, &child_pid, tgid_filtered, BPF_ANY);
                if (ret < 0)
                    tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);
            }
        }
    }

    if (!evaluate_scope_filters(&p))
        return 0;

    // Submit the event

    // Parent information.
    u64 parent_start_time = get_task_start_time(parent);
    int parent_tid = get_task_host_pid(parent);
    int parent_ns_pid = get_task_ns_tgid(parent);
    int parent_ns_tid = get_task_ns_pid(parent);

    // Parent (might be a thread or a process).
    save_to_submit_buf(&p.event->args_buf, (void *) &parent_tid, sizeof(int), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &parent_ns_tid, sizeof(int), 1);
    save_to_submit_buf(&p.event->args_buf, (void *) &parent_pid, sizeof(int), 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &parent_ns_pid, sizeof(int), 3);
    save_to_submit_buf(&p.event->args_buf, (void *) &parent_start_time, sizeof(u64), 4);

    // Child (might be a lwp or a process, sched_process_fork trace is calle by clone() also).
    save_to_submit_buf(&p.event->args_buf, (void *) &child_tid, sizeof(int), 5);
    save_to_submit_buf(&p.event->args_buf, (void *) &child_ns_tid, sizeof(int), 6);
    save_to_submit_buf(&p.event->args_buf, (void *) &child_pid, sizeof(int), 7);
    save_to_submit_buf(&p.event->args_buf, (void *) &child_ns_pid, sizeof(int), 8);
    save_to_submit_buf(&p.event->args_buf, (void *) &child_start_time, sizeof(u64), 9);

    // Process tree information (if needed).
    if (p.config->options & OPT_FORK_PROCTREE) {
        // Both, the thread group leader and the "parent_process" (the first process, not lwp, found
        // as a parent of the child in the hierarchy), are needed by the userland process tree.
        // The userland process tree default source of events is the signal events, but there is
        // an option to use regular event for maintaining it as well (and it is needed for some
        // situatins). These arguments will always be removed by userland event processors.
        struct task_struct *leader = get_leader_task(child);
        struct task_struct *parent_process = get_leader_task(get_parent_task(leader));

        // Parent Process information: Go up in hierarchy until parent is process.
        u64 parent_process_start_time = get_task_start_time(parent_process);
        int parent_process_pid = get_task_host_tgid(parent_process);
        int parent_process_tid = get_task_host_pid(parent_process);
        int parent_process_ns_pid = get_task_ns_tgid(parent_process);
        int parent_process_ns_tid = get_task_ns_pid(parent_process);
        // Leader information.
        u64 leader_start_time = get_task_start_time(leader);
        int leader_pid = get_task_host_tgid(leader);
        int leader_tid = get_task_host_pid(leader);
        int leader_ns_pid = get_task_ns_tgid(leader);
        int leader_ns_tid = get_task_ns_pid(leader);

        // Up Parent: always a process (might be the same as Parent if parent is a process).
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_process_tid, sizeof(int), 10);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_process_ns_tid, sizeof(int), 11);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_process_pid, sizeof(int), 12);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_process_ns_pid, sizeof(int), 13);
        save_to_submit_buf(
            &p.event->args_buf, (void *) &parent_process_start_time, sizeof(u64), 14);
        // Leader: always a process (might be the same as the Child if child is a process).
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_tid, sizeof(int), 15);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_ns_tid, sizeof(int), 16);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_pid, sizeof(int), 17);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_ns_pid, sizeof(int), 18);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_start_time, sizeof(u64), 19);
    }

    // Submit
    events_perf_submit(&p, 0);

    return 0;
}

#define MAX_NUM_MODULES          440
#define MAX_MODULES_MAP_ENTRIES  2 * MAX_NUM_MODULES
#define MOD_TREE_LOOP_ITERATIONS 240
#define MOD_TREE_LOOP_DEPTH      14
#define HISTORY_SCAN_FAILURE     0
#define HISTORY_SCAN_SUCCESSFUL  1

enum
{
    PROC_MODULES = 1 << 0,
    KSET = 1 << 1,
    MOD_TREE = 1 << 2,
    NEW_MOD = 1 << 3,
    HISTORY_SCAN_FINISHED = 1 << 4,
    FULL_SCAN = 1 << 30,
    HIDDEN_MODULE = 1 << 31,
};

// Forcibly create the map in all kernels, even when not needed, due to lack of
// support for kernel version awareness about map loading errors.

struct modules_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MODULES_MAP_ENTRIES);
    __type(key, u64);
    __type(value, kernel_module_t);
} modules_map SEC(".maps");

typedef struct modules_map modules_map_t;

struct new_module_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_NUM_MODULES);
    __type(key, u64);
    __type(value, kernel_new_mod_t);
} new_module_map SEC(".maps");

typedef struct new_module_map new_module_map_t;

typedef struct module_context_args {
    struct rb_node *curr;
    int iteration_num;
    int idx;
} module_context_args_t;

struct module_context_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, module_context_args_t);
} module_context_map SEC(".maps");

typedef struct module_context_map module_context_map_t;

// We only care for modules that got deleted or inserted between our scan and if
// we detected something suspicious. Since it's a very small time frame, it's
// not likely that a large amount of modules will be deleted. Instead of saving
// a map of deleted modules, we could have saved the last deleted module
// timestamp and, if we detected something suspicious, verify that no modules
// got deleted between our check. This is preferable space-wise (u64 instead of
// a map), but an attacker might start unloading modules in the background and
// race with the check in order to abort reporting for hidden modules.

struct recent_deleted_module_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50);
    __type(key, u64);
    __type(value, kernel_deleted_mod_t);
} recent_deleted_module_map SEC(".maps");

typedef struct recent_deleted_module_map recent_deleted_module_map_t;

u64 start_scan_time_init_shown_mods = 0;
u64 last_module_insert_time = 0;
bool hidden_old_mod_scan_done = false;

#define HID_MOD_RACE_CONDITION         -1
#define HID_MOD_UNCOMPLETED_ITERATIONS -2
#define HID_MOD_COMPLETED_ITERATIONS   0
#define HID_MOD_MEM_ZEROED             -3
#define MOD_HIDDEN                     1
#define MOD_NOT_HIDDEN                 0

void __always_inline lkm_seeker_send_to_userspace(struct module *mod, u32 *flags, program_data_t *p)
{
    // since this function can be called in a loop, we need to reset the buffer.
    // it is the responsibility of the caller, however, to set program_data to
    // the HIDDEN_KERNEL_MODULE_SEEKER event
    reset_event_args_buf(p->event);

    u64 mod_addr = (u64) mod;
    char *mod_name = mod->name;
    const char *mod_srcversion = BPF_CORE_READ(mod, srcversion);

    save_to_submit_buf(&(p->event->args_buf), &mod_addr, sizeof(u64), 0);
    save_bytes_to_buf(&(p->event->args_buf),
                      (void *) mod_name,
                      MODULE_NAME_LEN & MAX_MEM_DUMP_SIZE,
                      1); // string saved as bytes (verifier issues).
    save_to_submit_buf(&(p->event->args_buf), flags, sizeof(u32), 2);
    save_bytes_to_buf(&(p->event->args_buf),
                      (void *) mod_srcversion,
                      MODULE_SRCVERSION_MAX_LENGTH & MAX_MEM_DUMP_SIZE,
                      3); // string saved as bytes (verifier issues).

    events_perf_submit(p, 0);
}

// Populate all the modules to an efficient query-able hash map.
// We can't read it once and then hook on do_init_module and free_module since a hidden module will
// remove itself from the list directly and we wouldn't know (hence from our perspective the module
// will reside in the modules list, which could be false). So on every trigger, we go over the
// modules list and populate the map. It gets clean in userspace before every run.
// Since this mechanism is suppose to be triggered every once in a while,
// this should be ok.
statfunc int init_shown_modules()
{
    char modules_sym[8] = "modules";
    struct list_head *head = (struct list_head *) get_symbol_addr(modules_sym);
    kernel_module_t ker_mod = {};
    bool iterated_all_modules = false;
    struct module *pos, *n;

    pos = list_first_entry_ebpf(head, typeof(*pos), list);
    n = pos;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        pos = n;
        n = list_next_entry_ebpf(n, list);

        if (&pos->list == head) {
            return 0;
        }
        bpf_map_update_elem(&modules_map, &pos, &ker_mod, BPF_ANY);
    }

    return HID_MOD_UNCOMPLETED_ITERATIONS;
}

statfunc int is_hidden(u64 mod)
{
    if (bpf_map_lookup_elem(&modules_map, &mod) != NULL) {
        return MOD_NOT_HIDDEN;
    }

    // Verify that this module wasn't removed after we initialized modules_map
    kernel_deleted_mod_t *deleted_mod = bpf_map_lookup_elem(&recent_deleted_module_map, &mod);
    if (deleted_mod && deleted_mod->deleted_time > start_scan_time_init_shown_mods) {
        // This module got deleted after the start of the scan time.. So there
        // was a valid remove, and it's not hidden.
        return MOD_NOT_HIDDEN;
    }

    // Check if some module was inserted after we started scanning.
    // If that's the case, then if the module got inserted to the modules list after we walked on
    // the list, it'll be missing from our eBPF map. If it got inserted to other places (kset for
    // example), then it will appear as if the module is hidden (in kset but not in module's list),
    // but in fact it only got added in the midst of our scan. Thus, we need to monitor for this
    // situation.
    if (start_scan_time_init_shown_mods < last_module_insert_time) {
        // No point of checking other modules in this scan... abort
        return HID_MOD_RACE_CONDITION;
    }

    return MOD_HIDDEN;
}

statfunc int find_modules_from_module_kset_list(program_data_t *p)
{
    char module_kset_sym[12] = "module_kset";
    struct module *first_mod = NULL;
    struct kset *mod_kset = (struct kset *) get_symbol_addr(module_kset_sym);
    struct list_head *head = &(mod_kset->list);
    struct kobject *pos = list_first_entry_ebpf(head, typeof(*pos), entry);
    struct kobject *n = list_next_entry_ebpf(pos, entry);
    u32 flags = KSET;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        if (BPF_CORE_READ(n, name) ==
            NULL) { // Without this the list seems infinite. Also, using pos
                    // here seems incorrect as it starts from a weird member
            return 0;
        }

        struct module_kobject *mod_kobj =
            (struct module_kobject *) container_of(n, struct module_kobject, kobj);
        if (mod_kobj) {
            struct module *mod = BPF_CORE_READ(mod_kobj, mod);
            if (mod) {
                if (first_mod == NULL) {
                    first_mod = mod;
                } else if (first_mod == mod) { // Iterated over all modules - stop.
                    return 0;
                }
                int ret = is_hidden((u64) mod);
                if (ret == MOD_HIDDEN) {
                    lkm_seeker_send_to_userspace(mod, &flags, p);
                } else if (ret == HID_MOD_RACE_CONDITION) {
                    return ret;
                }
            }
        }

        pos = n;
        n = list_next_entry_ebpf(n, entry);
    }

    return HID_MOD_UNCOMPLETED_ITERATIONS;
}

struct walk_mod_tree_queue {
    __uint(max_entries, MAX_NUM_MODULES);
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, rb_node_t);
} walk_mod_tree_queue SEC(".maps");

typedef struct walk_mod_tree_queue walk_mod_tree_queue_t;

statfunc struct latch_tree_node *__lt_from_rb(struct rb_node *node, int idx)
{
    return container_of(node, struct latch_tree_node, node[idx]);
}

struct mod_tree_root {
    struct latch_tree_root root;
};

SEC("uprobe/lkm_seeker_modtree_loop_tail")
int lkm_seeker_modtree_loop(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    struct latch_tree_node *ltn;
    struct module *mod;
    u32 flags = MOD_TREE;

    int key = 0;
    module_context_args_t *module_ctx_args = bpf_map_lookup_elem(&module_context_map, &key);
    if (module_ctx_args == NULL)
        return -1;

    struct rb_node *curr = module_ctx_args->curr;
    int idx = module_ctx_args->idx;
    int iteration_num = module_ctx_args->iteration_num;

    int loop_result = HID_MOD_UNCOMPLETED_ITERATIONS;

#pragma unroll
    for (int i = 0; i < MOD_TREE_LOOP_ITERATIONS; i++) {
        if (curr != NULL) {
            rb_node_t rb_nod = {.node = curr};
            bpf_map_push_elem(&walk_mod_tree_queue, &rb_nod, BPF_EXIST);

            curr = BPF_CORE_READ(curr, rb_left); // Move left
        } else {
            rb_node_t rb_nod;
            if (bpf_map_pop_elem(&walk_mod_tree_queue, &rb_nod) != 0) {
                loop_result = HID_MOD_COMPLETED_ITERATIONS;
                break;
            } else {
                curr = rb_nod.node;
                ltn = __lt_from_rb(curr, idx);
                mod = BPF_CORE_READ(container_of(ltn, struct mod_tree_node, node), mod);

                int ret = is_hidden((u64) mod);
                if (ret == MOD_HIDDEN) {
                    lkm_seeker_send_to_userspace(mod, &flags, &p);
                } else if (ret == HID_MOD_RACE_CONDITION) {
                    loop_result = HID_MOD_RACE_CONDITION;
                    break;
                }

                /* We have visited the node and its left subtree.
                Now, it's right subtree's turn */
                curr = BPF_CORE_READ(curr, rb_right);
            }
        }
    }

    iteration_num++;

    if (loop_result == HID_MOD_COMPLETED_ITERATIONS) {
        flags = HISTORY_SCAN_FINISHED;
        lkm_seeker_send_to_userspace((struct module *) HISTORY_SCAN_SUCCESSFUL, &flags, &p);
        bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_PROC);
    } else if (loop_result == HID_MOD_RACE_CONDITION || iteration_num == MOD_TREE_LOOP_DEPTH) {
        flags = HISTORY_SCAN_FINISHED;
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_HID_KER_MOD, loop_result ^ iteration_num);
        lkm_seeker_send_to_userspace((struct module *) HISTORY_SCAN_FAILURE, &flags, &p);
        bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_PROC);
    }

    // Update context args for the next recursive call
    module_ctx_args->iteration_num = iteration_num;
    module_ctx_args->curr = curr;

    bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_MODTREE_LOOP);

    return -1;
}

statfunc int find_modules_from_mod_tree(program_data_t *p)
{
    char mod_tree_sym[9] = "mod_tree";
    struct mod_tree_root *m_tree = (struct mod_tree_root *) get_symbol_addr(mod_tree_sym);
    unsigned int seq;

    if (bpf_core_field_exists(m_tree->root.seq.sequence)) {
        seq = BPF_CORE_READ(m_tree, root.seq.sequence); // below 5.10
    } else {
        seq = BPF_CORE_READ(m_tree, root.seq.seqcount.sequence); // version >= v5.10
    }

    int idx = seq & 1;
    struct rb_node *root = BPF_CORE_READ(m_tree, root.tree[idx].rb_node);
    module_context_args_t module_ctx_args = {.idx = idx, .iteration_num = 0, .curr = root};

    int key = 0;
    bpf_map_update_elem(&module_context_map, &key, &module_ctx_args, BPF_ANY);

    bpf_tail_call(p->ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_MODTREE_LOOP);

    return -1;
}

static __always_inline u64 check_new_mods_only(program_data_t *p)
{
    struct module *pos, *n;
    u64 start_scan_time = get_current_time_in_ns();
    char modules_sym[8] = "modules";
    kernel_new_mod_t *new_mod;
    u64 mod_addr;
    struct list_head *head = (struct list_head *) get_symbol_addr(modules_sym);

    pos = list_first_entry_ebpf(head, typeof(*pos), list);
    n = pos;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        pos = n;
        n = list_next_entry_ebpf(n, list);
        if (&pos->list == head) {
            return start_scan_time; // To be used in userspace
        }

        mod_addr = (u64) pos;
        new_mod = bpf_map_lookup_elem(&new_module_map, &mod_addr);
        if (new_mod) {
            new_mod->last_seen_time = get_current_time_in_ns();
        }
    }

    return 0;
}

statfunc int check_is_proc_modules_hooked(program_data_t *p)
{
    struct module *pos, *n;
    u64 mod_base_addr;
    char modules_sym[8] = "modules";
    struct list_head *head = (struct list_head *) get_symbol_addr(modules_sym);
    u32 flags = PROC_MODULES | HIDDEN_MODULE;

    pos = list_first_entry_ebpf(head, typeof(*pos), list);
    n = pos;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        pos = n;
        n = list_next_entry_ebpf(n, list);
        if (&pos->list == head) {
            return 0;
        }

        // Check with the address being the start of the memory area, since
        // this is what is given from /proc/modules.
        if (bpf_core_field_exists(pos->mem)) { // Version >= v6.4
            mod_base_addr = (u64) BPF_CORE_READ(pos, mem[MOD_TEXT].base);
        } else {
            struct module___older_v64 *old_mod = (void *) pos;
            mod_base_addr = (u64) BPF_CORE_READ(old_mod, core_layout.base);
        }

        if (unlikely(mod_base_addr == 0)) { // Module memory was possibly tampered.. submit an error
            return HID_MOD_MEM_ZEROED;
        } else if (bpf_map_lookup_elem(&modules_map, &mod_base_addr) == NULL) {
            // Was there any recent insertion of a module since we populated
            // modules_list? if so, don't report as there's possible race
            // condition. Note that this granularity (insertion of any module
            // and not just this particular module) is only for /proc/modules
            // logic, since there's a context switch between userspace to kernel
            // space, it opens a window for more modules to get
            // inserted/deleted, and then the LRU size is not enough - modules
            // get evicted and we report a false-positive. We don't really want
            // the init_shown_mods time, but the time proc modules map was
            // filled (userspace) - so assume it happened max 2 seconds prior to
            // that.
            if (start_scan_time_init_shown_mods - (2 * 1000000000) < last_module_insert_time) {
                return 0;
            }

            // Module was not seen in proc modules and there was no recent insertion, report.
            lkm_seeker_send_to_userspace(pos, &flags, p);
        }
    }

    return HID_MOD_UNCOMPLETED_ITERATIONS;
}

statfunc bool kern_ver_below_min_lkm(struct pt_regs *ctx)
{
    // If we're below kernel version 5.2, propogate error to userspace and return
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_sk_storage_get)) {
        goto below_threshold;
    }

    return false; // lkm seeker may run!

    goto below_threshold; // For compiler - avoid "unused label" warning
below_threshold:
    tracee_log(ctx,
               BPF_LOG_LVL_ERROR,
               BPF_LOG_ID_UNSPEC,
               -1); // notify the user that the event logic isn't loaded even though it's requested
    return true;
}

SEC("uprobe/lkm_seeker_submitter")
int uprobe_lkm_seeker_submitter(struct pt_regs *ctx)
{
    // This check is to satisfy the verifier for kernels older than 5.2
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    u64 mod_address = 0;
    u64 received_flags = 0;

#if defined(bpf_target_x86)
    mod_address = ctx->bx;    // 1st arg
    received_flags = ctx->cx; // 2nd arg
#elif defined(bpf_target_arm64)
    mod_address = ctx->user_regs.regs[1];    // 1st arg
    received_flags = ctx->user_regs.regs[2]; // 2nd arg
#else
    return 0;
#endif

    program_data_t p = {};
    if (!init_program_data(&p, ctx, HIDDEN_KERNEL_MODULE_SEEKER))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;

    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;
    // Uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    u32 flags =
        ((u32) received_flags) | HIDDEN_MODULE; // Convert to 32bit and turn on the bit that will
                                                // cause it to be sent as an event to the user
    lkm_seeker_send_to_userspace((struct module *) mod_address, &flags, &p);

    return 0;
}

// There are 2 types of scans:
// - Scan of modules that were loaded prior tracee started: this is only done once at the start of
// tracee
// - Scan of modules that were loaded after tracee started: runs periodically and on each new module
// insertion
SEC("uprobe/lkm_seeker")
int uprobe_lkm_seeker(struct pt_regs *ctx)
{
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    program_data_t p = {};
    if (!init_program_data(&p, ctx, HIDDEN_KERNEL_MODULE_SEEKER))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != p.task_info->context.pid &&
        p.config->tracee_pid != p.task_info->context.host_pid) {
        return 0;
    }

    start_scan_time_init_shown_mods = get_current_time_in_ns();
    int ret = init_shown_modules();
    if (ret != 0) {
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_HID_KER_MOD, ret);
        return 1;
    }

    // On first run, do a scan only relevant for modules that were inserted prior tracee started.
    if (unlikely(!hidden_old_mod_scan_done)) {
        hidden_old_mod_scan_done = true;
        bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_KSET);
        return -1;
    }

    bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_PROC);

    return -1;
}

SEC("uprobe/lkm_seeker_kset_tail")
int lkm_seeker_kset_tail(struct pt_regs *ctx)
{
    // This check is to satisfy the verifier for kernels older than 5.2
    // as in runtime we'll never get here (the tail call doesn't happen)
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    int ret = find_modules_from_module_kset_list(&p);
    if (ret < 0) {
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_HID_KER_MOD, ret);
        u32 flags = HISTORY_SCAN_FINISHED;
        lkm_seeker_send_to_userspace(
            (struct module *) HISTORY_SCAN_FAILURE, &flags, &p); // Report failure of history scan
        return -1;
    }

    bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_MOD_TREE);

    return -1;
}

SEC("uprobe/lkm_seeker_mod_tree_tail")
int lkm_seeker_mod_tree_tail(struct pt_regs *ctx)
{
    // This check is to satisfy the verifier for kernels older than 5.2
    // as in runtime we'll never get here (the tail call doesn't happen)
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    u32 flags = HISTORY_SCAN_FINISHED;

    // This method is efficient only when the kernel is compiled with
    // CONFIG_MODULES_TREE_LOOKUP=y
    find_modules_from_mod_tree(&p);

    bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_PROC);
    return -1;
}

SEC("uprobe/lkm_seeker_proc_tail")
int lkm_seeker_proc_tail(struct pt_regs *ctx)
{
    // This check is to satisfy the verifier for kernels older than 5.2
    // as in runtime we'll never get here (the tail call doesn't happen)
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    int ret = check_is_proc_modules_hooked(&p);
    if (ret < 0) {
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_HID_KER_MOD, ret);
        return -1;
    }

    bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_NEW_MOD_ONLY);

    return -1;
}

// We maintain a map of newly loaded modules. At times, we verify that this module appears in
// modules list. If it is not (and there was no valid deletion), then it's hidden.
SEC("uprobe/lkm_seeker_new_mod_only_tail")
int lkm_seeker_new_mod_only_tail(struct pt_regs *ctx)
{
    // This check is to satisfy the verifier for kernels older than 5.2
    // as in runtime we'll never get here (the tail call doesn't happen)
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    u64 start_scan_time = check_new_mods_only(&p);
    if (start_scan_time == 0) {
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_HID_KER_MOD, HID_MOD_UNCOMPLETED_ITERATIONS);
        return -1;
    }

    struct module *mod =
        (struct module *) start_scan_time; // Use the module address field as the start_scan_time
    u32 flags = NEW_MOD;
    lkm_seeker_send_to_userspace(mod, &flags, &p);

    return 0;
}

// clang-format off

// trace/events/sched.h: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SCHED_PROCESS_EXEC))
        return 0;
    
    // Reset thread stack area
    p.task_info->stack = (address_range_t){0};

    // Perform checks below before evaluate_scope_filters(), so tracee can filter by newly created containers
    // or processes. Assume that a new container, or pod, has started when a process of a newly
    // created cgroup and mount ns executed a binary.

    if (p.task_info->container_state == CONTAINER_CREATED) {
        u32 mntns = get_task_mnt_ns_id(p.event->task);
        struct task_struct *parent = get_parent_task(p.event->task);
        u32 parent_mntns = get_task_mnt_ns_id(parent);
        if (mntns != parent_mntns) {
            u32 cgroup_id_lsb = p.event->context.task.cgroup_id;
            u8 state = CONTAINER_STARTED;
            bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
            p.task_info->container_state = state;
            p.event->context.task.flags |= CONTAINER_STARTED_FLAG; // change for current event
            p.task_info->context.flags |= CONTAINER_STARTED_FLAG;  // change for future task events
        }
    }

    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    if (bprm == NULL)
        return -1;

    struct file *file = get_file_ptr_from_bprm(bprm);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));

    proc_info_t *proc_info = p.proc_info;
    proc_info->follow_in_scopes = get_scopes_to_follow(&p); // follow task for matched scopes
    proc_info->new_proc = true; // task has started after tracee started running

    // Extract the binary name to be used in evaluate_scope_filters
    __builtin_memset(proc_info->binary.path, 0, MAX_BIN_PATH_SIZE);
    bpf_probe_read_kernel_str(proc_info->binary.path, MAX_BIN_PATH_SIZE, file_path);
    proc_info->binary.mnt_id = p.event->context.task.mnt_id;

    if (!evaluate_scope_filters(&p))
        return 0;

    // Note: From v5.9+, there are two interesting fields in bprm that could be added:
    // 1. struct file *executable: the executable name passed to an interpreter
    // 2. fdpath: generated filename for execveat (after resolving dirfd)

    const char *filename = get_binprm_filename(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);
    umode_t inode_mode = get_inode_mode_from_file(file);

    save_str_to_buf(&p.event->args_buf, (void *) filename, 0);                   // executable name
    save_str_to_buf(&p.event->args_buf, file_path, 1);                           // executable path
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 2);            // device number
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 3); // inode number 
    save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);              // changed time
    save_to_submit_buf(&p.event->args_buf, &inode_mode, sizeof(umode_t), 5);     // inode mode

    // NOTES:
    // - interp is the real interpreter (sh, bash, python, perl, ...)
    // - interpreter is the binary interpreter (ld.so), also known as the loader
    // - interpreter might be the same as executable (so there is no interpreter)

    // Check if there is an interpreter and if it is different from the executable:

    bool itp_inode_exists = proc_info->interpreter.id.inode != 0;
    bool itp_dev_diff = proc_info->interpreter.id.device != s_dev;
    bool itp_inode_diff = proc_info->interpreter.id.inode != inode_nr;

    if (itp_inode_exists && (itp_dev_diff || itp_inode_diff)) {
        save_str_to_buf(&p.event->args_buf, &proc_info->interpreter.pathname, 6);                    // interpreter path
        save_to_submit_buf(&p.event->args_buf, &proc_info->interpreter.id.device, sizeof(dev_t), 7); // interpreter device number
        save_to_submit_buf(&p.event->args_buf, &proc_info->interpreter.id.inode, sizeof(u64), 8);    // interpreter inode number
        save_to_submit_buf(&p.event->args_buf, &proc_info->interpreter.id.ctime, sizeof(u64), 9);    // interpreter changed time
    }

    bpf_tail_call(ctx, &prog_array_tp, TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT);

    return 0;
}

// clang-format on

SEC("raw_tracepoint/sched_process_exec_event_submit_tail")
int sched_process_exec_event_submit_tail(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];

    if (bprm == NULL)
        return -1;

    // bprm->mm is null at this point (set by begin_new_exec()), and task->mm is already initialized
    struct mm_struct *mm = get_mm_from_task(task);

    unsigned long arg_start, arg_end;
    arg_start = get_arg_start_from_mm(mm);
    arg_end = get_arg_end_from_mm(mm);
    int argc = get_argc_from_bprm(bprm);

    struct file *stdin_file = get_struct_file_from_fd(0);
    unsigned short stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
    void *stdin_path = get_path_str(__builtin_preserve_access_index(&stdin_file->f_path));
    const char *interp = get_binprm_interp(bprm);

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD) {
        invoked_from_kernel = 1;
    }

    save_args_str_arr_to_buf(&p.event->args_buf, (void *) arg_start, (void *) arg_end, argc, 10);
    save_str_to_buf(&p.event->args_buf, (void *) interp, 11);
    save_to_submit_buf(&p.event->args_buf, &stdin_type, sizeof(unsigned short), 12);
    save_str_to_buf(&p.event->args_buf, stdin_path, 13);
    save_to_submit_buf(&p.event->args_buf, &invoked_from_kernel, sizeof(int), 14);
    save_str_to_buf(&p.event->args_buf, (void *) p.task_info->context.comm, 15);
    if (p.config->options & OPT_EXEC_ENV) {
        unsigned long env_start, env_end;
        env_start = get_env_start_from_mm(mm);
        env_end = get_env_end_from_mm(mm);
        int envc = get_envc_from_bprm(bprm);

        save_args_str_arr_to_buf(
            &p.event->args_buf, (void *) env_start, (void *) env_end, envc, 16);
    }

    events_perf_submit(&p, 0);
    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SCHED_PROCESS_EXIT))
        return 0;

    // evaluate matched_policies before removing this pid from the maps
    evaluate_scope_filters(&p);

    bpf_map_delete_elem(&task_info_map, &p.event->context.task.host_tid);

    if (!policies_matched(p.event))
        return 0;

    long exit_code = get_task_exit_code(p.event->task);
    bool group_dead = false;
    struct task_struct *task = p.event->task;
    struct signal_struct *signal = BPF_CORE_READ(task, signal);
    atomic_t live = BPF_CORE_READ(signal, live);
    // This check could be true for multiple thread exits if the thread count was 0 when the hooks
    // were triggered. This could happen for example if the threads performed exit in different CPUs
    // simultaneously.
    if (live.counter == 0) {
        group_dead = true;
    }

    save_to_submit_buf(&p.event->args_buf, (void *) &exit_code, sizeof(long), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &group_dead, sizeof(bool), 1);

    events_perf_submit(&p, 0);

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_free")
int tracepoint__sched__sched_process_free(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) ctx->args[0];

    int pid = get_task_host_pid(task);
    int tgid = get_task_host_tgid(task);

    if (pid == tgid) {
        // we only care about process (and not thread) exit
        // if tgid task is freed, we know for sure that the process exited
        // so we can safely remove it from the process map
        bpf_map_delete_elem(&proc_info_map, &tgid);

        u32 zero = 0;
        config_entry_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
        if (unlikely(cfg == NULL))
            return 0;

        // remove it only from the current policies version map
        u16 version = cfg->policies_version;

        // Give the compiler a hint about the map type, otherwise libbpf will complain
        // about missing type information. i.e.: "can't determine value size for type".
        process_tree_map_t *inner_proc_tree_map = &process_tree_map;

        inner_proc_tree_map = bpf_map_lookup_elem(&process_tree_map_version, &version);
        if (inner_proc_tree_map != NULL)
            bpf_map_delete_elem(inner_proc_tree_map, &tgid);
    }

    return 0;
}

SEC("raw_tracepoint/syscall__accept4")
int syscall__accept4(void *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, SOCKET_ACCEPT) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(SOCKET_ACCEPT);

    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    if (!reset_event(p.event, SOCKET_ACCEPT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct socket *old_sock = (struct socket *) saved_args.args[0];
    struct socket *new_sock = (struct socket *) saved_args.args[1];
    u64 sockfd = (u32) saved_args.args[2];

    if (new_sock == NULL) {
        return -1;
    }
    if (old_sock == NULL) {
        return -1;
    }

    save_to_submit_buf(&p.event->args_buf, (void *) &sockfd, sizeof(u32), 0);
    save_sockaddr_to_buf(&p.event->args_buf, old_sock, 1);
    save_sockaddr_to_buf(&p.event->args_buf, new_sock, 2);

    return events_perf_submit(&p, 0);
}

// trace/events/sched.h: TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SCHED_SWITCH))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct task_struct *prev = (struct task_struct *) ctx->args[1];
    struct task_struct *next = (struct task_struct *) ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(&p.event->args_buf, (void *) &cpu, sizeof(int), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &prev_pid, sizeof(int), 1);
    save_str_to_buf(&p.event->args_buf, prev->comm, 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &next_pid, sizeof(int), 3);
    save_str_to_buf(&p.event->args_buf, next->comm, 4);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/filldir64")
int BPF_KPROBE(trace_filldir64)
{
    // only inode=0 is relevant, simple filter prior to program run
    unsigned long process_inode_number = (unsigned long) PT_REGS_PARM5(ctx);
    if (process_inode_number != 0)
        return 0;

    program_data_t p = {};
    if (!init_program_data(&p, ctx, HIDDEN_INODES))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    char *process_name = (char *) PT_REGS_PARM2(ctx);

    save_str_to_buf(&p.event->args_buf, process_name, 0);
    return events_perf_submit(&p, 0);
}

SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(trace_call_usermodehelper)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CALL_USERMODE_HELPER))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    void *path = (void *) PT_REGS_PARM1(ctx);
    unsigned long argv = PT_REGS_PARM2(ctx);
    unsigned long envp = PT_REGS_PARM3(ctx);
    int wait = PT_REGS_PARM4(ctx);

    save_str_to_buf(&p.event->args_buf, path, 0);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) argv, 1);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) envp, 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &wait, sizeof(int), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, DO_EXIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    long code = PT_REGS_PARM1(ctx);

    return events_perf_submit(&p, code);
}

statfunc void syscall_table_check(program_data_t *p)
{
    char sys_call_table_symbol[15] = "sys_call_table";
    u64 *sys_call_table = (u64 *) get_symbol_addr(sys_call_table_symbol);

    int index = 0; // For the verifier

#pragma unroll
    for (int i = 0; i < MAX_SYS_CALL_TABLE_SIZE; i++) {
        index = i;
        syscall_table_entry_t *expected_entry =
            bpf_map_lookup_elem(&expected_sys_call_table, &index);

        if (!expected_entry || expected_entry->address == 0)
            continue;

        u64 effective_address;
        bpf_probe_read_kernel(&effective_address, sizeof(u64), sys_call_table + index);

        if (expected_entry->address == effective_address)
            continue;

        // it is the responsibility of the caller to set program_data to the
        // SYSCALL_TABLE_CHECK event
        reset_event_args_buf(p->event);

        save_to_submit_buf(&(p->event->args_buf), &index, sizeof(int), 0);
        save_to_submit_buf(&(p->event->args_buf), &effective_address, sizeof(u64), 1);

        events_perf_submit(p, 0);
    }
}

// syscall_table_check
SEC("uprobe/syscall_table_check")
int uprobe_syscall_table_check(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SYSCALL_TABLE_CHECK))
        return 0;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != p.task_info->context.pid &&
        p.config->tracee_pid != p.task_info->context.host_pid)
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;

    syscall_table_check(&p);

    return 0;
}

SEC("uprobe/trigger_seq_ops_event")
int uprobe_seq_ops_trigger(struct pt_regs *ctx)
{
    u64 caller_ctx_id = 0;
    u64 *address_array = NULL;
    u64 struct_address = 0;

    // clang-format off
    //
    // Golang calling convention per architecture

    #if defined(bpf_target_x86)
        caller_ctx_id = ctx->bx;                // 1st arg
        address_array = ((void *) ctx->sp + 8); // 2nd arg
    #elif defined(bpf_target_arm64)
        caller_ctx_id = ctx->user_regs.regs[1]; // 1st arg
        address_array = ((void *) ctx->sp + 8); // 2nd arg

    #else
        return 0;
    #endif
    // clang-format on

    program_data_t p = {};
    if (!init_program_data(&p, ctx, PRINT_NET_SEQ_OPS))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != p.task_info->context.pid &&
        p.config->tracee_pid != p.task_info->context.host_pid)
        return 0;

    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    u32 count_off = p.event->args_buf.offset + 1;
    save_u64_arr_to_buf(&p.event->args_buf, NULL, 0, 0); // init u64 array with size 0

#pragma unroll
    for (int i = 0; i < NET_SEQ_OPS_TYPES; i++) {
        bpf_probe_read_user(&struct_address, 8, (address_array + i));
        struct seq_operations *seq_ops = (struct seq_operations *) struct_address;

        u64 show_addr = (u64) BPF_CORE_READ(seq_ops, show);
        if (show_addr == 0)
            return 0;
        if (show_addr >= (u64) stext_addr && show_addr < (u64) etext_addr)
            show_addr = 0;

        u64 start_addr = (u64) BPF_CORE_READ(seq_ops, start);
        if (start_addr == 0)
            return 0;
        if (start_addr >= (u64) stext_addr && start_addr < (u64) etext_addr)
            start_addr = 0;

        u64 next_addr = (u64) BPF_CORE_READ(seq_ops, next);
        if (next_addr == 0)
            return 0;
        if (next_addr >= (u64) stext_addr && next_addr < (u64) etext_addr)
            next_addr = 0;

        u64 stop_addr = (u64) BPF_CORE_READ(seq_ops, stop);
        if (stop_addr == 0)
            return 0;
        if (stop_addr >= (u64) stext_addr && stop_addr < (u64) etext_addr)
            stop_addr = 0;

        u64 seq_ops_addresses[NET_SEQ_OPS_SIZE + 1] = {show_addr, start_addr, next_addr, stop_addr};

        add_u64_elements_to_buf(&p.event->args_buf, (const u64 *) seq_ops_addresses, 4, count_off);
    }

    save_to_submit_buf(&p.event->args_buf, (void *) &caller_ctx_id, sizeof(uint64_t), 1);
    events_perf_submit(&p, 0);
    return 0;
}

SEC("uprobe/trigger_mem_dump_event")
int uprobe_mem_dump_trigger(struct pt_regs *ctx)
{
    u64 address = 0;
    u64 size = 0;
    u64 caller_ctx_id = 0;

#if defined(bpf_target_x86)
    address = ctx->bx;       // 1st arg
    size = ctx->cx;          // 2nd arg
    caller_ctx_id = ctx->di; // 3rd arg
#elif defined(bpf_target_arm64)
    address = ctx->user_regs.regs[1];        // 1st arg
    size = ctx->user_regs.regs[2];           // 2nd arg
    caller_ctx_id = ctx->user_regs.regs[3];  // 3rd arg
#else
    return 0;
#endif

    program_data_t p = {};
    if (!init_program_data(&p, ctx, PRINT_MEM_DUMP))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != p.task_info->context.pid &&
        p.config->tracee_pid != p.task_info->context.host_pid)
        return 0;

    if (size <= 0)
        return 0;

    int ret = save_bytes_to_buf(&p.event->args_buf, (void *) address, size & MAX_MEM_DUMP_SIZE, 0);
    // return in case of failed pointer read
    if (ret == 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_MEM_READ, ret);
        return 0;
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &address, sizeof(void *), 1);
    save_to_submit_buf(&p.event->args_buf, &size, sizeof(u64), 2);
    save_to_submit_buf(&p.event->args_buf, &caller_ctx_id, sizeof(u64), 3);

    return events_perf_submit(&p, 0);
}

statfunc struct trace_kprobe *get_trace_kprobe_from_trace_probe(void *tracep)
{
    struct trace_kprobe *tracekp =
        (struct trace_kprobe *) container_of(tracep, struct trace_kprobe, tp);

    return tracekp;
}

statfunc struct trace_uprobe *get_trace_uprobe_from_trace_probe(void *tracep)
{
    struct trace_uprobe *traceup =
        (struct trace_uprobe *) container_of(tracep, struct trace_uprobe, tp);

    return traceup;
}

// This function returns a pointer to struct trace_probe from struct trace_event_call.
statfunc void *get_trace_probe_from_trace_event_call(struct trace_event_call *call)
{
    void *tracep_ptr;

    struct trace_probe___v53 *legacy_tracep;
    if (bpf_core_field_exists(legacy_tracep->call)) {
        tracep_ptr = container_of(call, struct trace_probe___v53, call);
    } else {
        struct trace_probe_event *tpe = container_of(call, struct trace_probe_event, call);
        struct list_head probes = BPF_CORE_READ(tpe, probes);
        tracep_ptr = container_of(probes.next, struct trace_probe, list);
    }

    return tracep_ptr;
}

enum bpf_attach_type_e
{
    BPF_RAW_TRACEPOINT,
    PERF_TRACEPOINT,
    PERF_KPROBE,
    PERF_KRETPROBE,
    PERF_UPROBE,
    PERF_URETPROBE
};

statfunc int send_bpf_attach(
    program_data_t *p, struct bpf_prog *prog, void *event_name, u64 probe_addr, int perf_type)
{
    // get bpf prog details

    int prog_type = BPF_CORE_READ(prog, type);
    struct bpf_prog_aux *prog_aux = BPF_CORE_READ(prog, aux);
    u32 prog_id = BPF_CORE_READ(prog_aux, id);
    char prog_name[BPF_OBJ_NAME_LEN];
    bpf_probe_read_kernel_str(&prog_name, BPF_OBJ_NAME_LEN, prog_aux->name);

    // get usage of helpers
    bpf_used_helpers_t *val = bpf_map_lookup_elem(&bpf_attach_map, &prog_id);
    if (val == NULL)
        return 0;

    // submit the event

    save_to_submit_buf(&(p->event->args_buf), &prog_type, sizeof(int), 0);
    save_str_to_buf(&(p->event->args_buf), (void *) &prog_name, 1);
    save_to_submit_buf(&(p->event->args_buf), &prog_id, sizeof(u32), 2);
    save_u64_arr_to_buf(&(p->event->args_buf), (const u64 *) val->helpers, 4, 3);
    save_str_to_buf(&(p->event->args_buf), event_name, 4);
    save_to_submit_buf(&(p->event->args_buf), &probe_addr, sizeof(u64), 5);
    save_to_submit_buf(&(p->event->args_buf), &perf_type, sizeof(int), 6);

    events_perf_submit(p, 0);

    // delete from map
    bpf_map_delete_elem(&bpf_attach_map, &prog_id);

    return 0;
}

// Inspired by bpf_get_perf_event_info() kernel func.
// https://elixir.bootlin.com/linux/v5.19.2/source/kernel/trace/bpf_trace.c#L2123
statfunc int
send_bpf_perf_attach(program_data_t *p, struct file *bpf_prog_file, struct file *perf_event_file)
{
    // get real values of TRACE_EVENT_FL_KPROBE and TRACE_EVENT_FL_UPROBE.
    // these values were changed in kernels >= 5.15.
    int TRACE_EVENT_FL_KPROBE_BIT;
    int TRACE_EVENT_FL_UPROBE_BIT;
    if (bpf_core_field_exists(((struct trace_event_call *) 0)->module)) { // kernel >= 5.15
        TRACE_EVENT_FL_KPROBE_BIT = 6;
        TRACE_EVENT_FL_UPROBE_BIT = 7;
    } else { // kernel < 5.15
        TRACE_EVENT_FL_KPROBE_BIT = 5;
        TRACE_EVENT_FL_UPROBE_BIT = 6;
    }
    int TRACE_EVENT_FL_KPROBE = (1 << TRACE_EVENT_FL_KPROBE_BIT);
    int TRACE_EVENT_FL_UPROBE = (1 << TRACE_EVENT_FL_UPROBE_BIT);

    // get perf event details

// clang-format off
#define MAX_PERF_EVENT_NAME ((MAX_PATH_PREF_SIZE > MAX_KSYM_NAME_SIZE) ? MAX_PATH_PREF_SIZE : MAX_KSYM_NAME_SIZE)
#define REQUIRED_SYSTEM_LENGTH 9
    // clang-format on

    struct perf_event *event = (struct perf_event *) BPF_CORE_READ(perf_event_file, private_data);
    struct trace_event_call *tp_event = BPF_CORE_READ(event, tp_event);
    char event_name[MAX_PERF_EVENT_NAME];
    u64 probe_addr = 0;
    int perf_type;

    int flags = BPF_CORE_READ(tp_event, flags);

    // check if syscall_tracepoint
    bool is_syscall_tracepoint = false;
    struct trace_event_class *tp_class = BPF_CORE_READ(tp_event, class);
    char class_system[REQUIRED_SYSTEM_LENGTH];
    bpf_probe_read_kernel_str(
        &class_system, REQUIRED_SYSTEM_LENGTH, BPF_CORE_READ(tp_class, system));
    class_system[REQUIRED_SYSTEM_LENGTH - 1] = '\0';
    if (strncmp("syscalls", class_system, REQUIRED_SYSTEM_LENGTH - 1) == 0) {
        is_syscall_tracepoint = true;
    }

    if (flags & TRACE_EVENT_FL_TRACEPOINT) { // event is tracepoint

        perf_type = PERF_TRACEPOINT;
        struct tracepoint *tp = BPF_CORE_READ(tp_event, tp);
        bpf_probe_read_kernel_str(&event_name, MAX_KSYM_NAME_SIZE, BPF_CORE_READ(tp, name));

    } else if (is_syscall_tracepoint) { // event is syscall tracepoint

        perf_type = PERF_TRACEPOINT;
        bpf_probe_read_kernel_str(&event_name, MAX_KSYM_NAME_SIZE, BPF_CORE_READ(tp_event, name));

    } else {
        bool is_ret_probe = false;
        void *tracep_ptr = get_trace_probe_from_trace_event_call(tp_event);

        if (flags & TRACE_EVENT_FL_KPROBE) { // event is kprobe

            struct trace_kprobe *tracekp = get_trace_kprobe_from_trace_probe(tracep_ptr);

            // check if probe is a kretprobe
            struct kretprobe *krp = &tracekp->rp;
            kretprobe_handler_t handler_f = BPF_CORE_READ(krp, handler);
            if (handler_f != NULL)
                is_ret_probe = true;

            if (is_ret_probe)
                perf_type = PERF_KRETPROBE;
            else
                perf_type = PERF_KPROBE;

            // get symbol name
            bpf_probe_read_kernel_str(
                &event_name, MAX_KSYM_NAME_SIZE, BPF_CORE_READ(tracekp, symbol));

            // get symbol address
            if (!event_name[0])
                probe_addr = (unsigned long) BPF_CORE_READ(krp, kp.addr);

        } else if (flags & TRACE_EVENT_FL_UPROBE) { // event is uprobe

            struct trace_uprobe *traceup = get_trace_uprobe_from_trace_probe(tracep_ptr);

            // determine if ret probe
            struct uprobe_consumer *upc = &traceup->consumer;
            void *handler_f = BPF_CORE_READ(upc, ret_handler);
            if (handler_f != NULL)
                is_ret_probe = true;

            if (is_ret_probe)
                perf_type = PERF_URETPROBE;
            else
                perf_type = PERF_UPROBE;

            // get binary path
            bpf_probe_read_kernel_str(
                &event_name, MAX_PATH_PREF_SIZE, BPF_CORE_READ(traceup, filename));

            // get symbol offset
            probe_addr = BPF_CORE_READ(traceup, offset);

        } else {
            // unsupported perf type
            return 0;
        }
    }

    struct bpf_prog *prog = (struct bpf_prog *) BPF_CORE_READ(bpf_prog_file, private_data);

    return send_bpf_attach(p, prog, &event_name, probe_addr, perf_type);
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(trace_security_file_ioctl)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, BPF_ATTACH))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    unsigned int cmd = PT_REGS_PARM2(ctx);

    if (cmd == PERF_EVENT_IOC_SET_BPF) {
        struct file *perf_event_file = (struct file *) PT_REGS_PARM1(ctx);
        unsigned long fd = PT_REGS_PARM3(ctx);
        struct file *bpf_prog_file = get_struct_file_from_fd(fd);

        send_bpf_perf_attach(&p, bpf_prog_file, perf_event_file);
    }

    return 0;
}

SEC("kprobe/tracepoint_probe_register_prio_may_exist")
int BPF_KPROBE(trace_tracepoint_probe_register_prio_may_exist)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, BPF_ATTACH))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct tracepoint *tp = (struct tracepoint *) PT_REGS_PARM1(ctx);
    struct bpf_prog *prog = (struct bpf_prog *) PT_REGS_PARM3(ctx);

    char event_name[MAX_PERF_EVENT_NAME];
    bpf_probe_read_kernel_str(&event_name, MAX_KSYM_NAME_SIZE, BPF_CORE_READ(tp, name));

    int perf_type = BPF_RAW_TRACEPOINT;
    u64 probe_addr = 0;

    return send_bpf_attach(&p, prog, &event_name, probe_addr, perf_type);
}

// trace/events/cgroup.h:
// TP_PROTO(struct cgroup *dst_cgrp, const char *path, struct task_struct *task, bool threadgroup)
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CGROUP_ATTACH_TASK))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    char *path = (char *) ctx->args[1];
    struct task_struct *task = (struct task_struct *) ctx->args[2];

    int pid = get_task_host_pid(task);
    char *comm = BPF_CORE_READ(task, comm);

    save_str_to_buf(&p.event->args_buf, path, 0);
    save_str_to_buf(&p.event->args_buf, comm, 1);
    save_to_submit_buf(&p.event->args_buf, (void *) &pid, sizeof(int), 2);
    events_perf_submit(&p, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CGROUP_MKDIR))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    save_to_submit_buf(&p.event->args_buf, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&p.event->args_buf, path, 1);
    save_to_submit_buf(&p.event->args_buf, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&p, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CGROUP_RMDIR))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    save_to_submit_buf(&p.event->args_buf, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&p.event->args_buf, path, 1);
    save_to_submit_buf(&p.event->args_buf, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&p, 0);

    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPRM_CHECK))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    struct file *file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));

    syscall_data_t *sys = &p.task_info->syscall_data;
    const char *const *argv = NULL;
    const char *const *envp = NULL;
    switch (sys->id) {
        case SYSCALL_EXECVE:
            argv = (const char *const *) sys->args.args[1];
            envp = (const char *const *) sys->args.args[2];
            break;
        case SYSCALL_EXECVEAT:
            argv = (const char *const *) sys->args.args[2];
            envp = (const char *const *) sys->args.args[3];
            break;
        default:
            break;
    }

    save_str_to_buf(&p.event->args_buf, file_path, 0);
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 2);
    save_str_arr_to_buf(&p.event->args_buf, argv, 3);
    if (p.config->options & OPT_EXEC_ENV)
        save_str_arr_to_buf(&p.event->args_buf, envp, 4);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_FILE_OPEN))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    // Load the arguments given to the open syscall (which eventually invokes this function)
    char empty_string[1] = "";
    void *syscall_pathname = &empty_string;
    struct pt_regs *task_regs = get_current_task_pt_regs();

    switch (p.event->context.syscall) {
        case SYSCALL_EXECVE:
        case SYSCALL_OPEN:
            syscall_pathname = (void *) get_syscall_arg1(p.event->task, task_regs, false);
            break;

        case SYSCALL_EXECVEAT:
        case SYSCALL_OPENAT:
        case SYSCALL_OPENAT2:
            syscall_pathname = (void *) get_syscall_arg2(p.event->task, task_regs, false);
            break;
    }

    save_str_to_buf(&p.event->args_buf, file_path, 0);
    save_to_submit_buf(&p.event->args_buf,
                       (void *) __builtin_preserve_access_index(&file->f_flags),
                       sizeof(int),
                       1);
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);
    save_str_to_buf(&p.event->args_buf, syscall_pathname, 5);

    if (!evaluate_data_filters(&p, 0))
        return 0;

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_security_sb_mount)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SB_MOUNT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    const char *dev_name = (const char *) PT_REGS_PARM1(ctx);
    struct path *path = (struct path *) PT_REGS_PARM2(ctx);
    const char *type = (const char *) PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long) PT_REGS_PARM4(ctx);

    void *path_str = get_path_str(path);

    save_str_to_buf(&p.event->args_buf, (void *) dev_name, 0);
    save_str_to_buf(&p.event->args_buf, path_str, 1);
    save_str_to_buf(&p.event->args_buf, (void *) type, 2);
    save_to_submit_buf(&p.event->args_buf, &flags, sizeof(unsigned long), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_INODE_UNLINK))
        return 0;

    file_id_t unlinked_file_id = {};

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    unlinked_file_id.inode = get_inode_nr_from_dentry(dentry);
    unlinked_file_id.device = get_dev_from_dentry(dentry);

    if ((p.config->options & (OPT_CAPTURE_FILES_READ | OPT_CAPTURE_FILES_WRITE)) != 0) {
        // We want to avoid reacquisition of the same inode-device affecting capture behavior
        unlinked_file_id.ctime = 0;
        bpf_map_delete_elem(&elf_files_map, &unlinked_file_id);
    }

    if (!evaluate_scope_filters(&p))
        return 0;

    void *dentry_path = get_dentry_path_str(dentry);
    unlinked_file_id.ctime = get_ctime_nanosec_from_dentry(dentry);

    save_str_to_buf(&p.event->args_buf, dentry_path, 0);
    save_to_submit_buf(&p.event->args_buf, &unlinked_file_id.inode, sizeof(unsigned long), 1);
    save_to_submit_buf(&p.event->args_buf, &unlinked_file_id.device, sizeof(dev_t), 2);
    save_to_submit_buf(&p.event->args_buf, &unlinked_file_id.ctime, sizeof(u64), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, COMMIT_CREDS))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct cred *new_cred = (struct cred *) PT_REGS_PARM1(ctx);
    struct cred *old_cred = (struct cred *) get_task_real_cred(p.event->task);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    struct user_namespace *userns_old = BPF_CORE_READ(old_cred, user_ns);
    struct user_namespace *userns_new = BPF_CORE_READ(new_cred, user_ns);

    // old credentials

    old_slim.uid = BPF_CORE_READ(old_cred, uid.val);
    old_slim.gid = BPF_CORE_READ(old_cred, gid.val);
    old_slim.suid = BPF_CORE_READ(old_cred, suid.val);
    old_slim.sgid = BPF_CORE_READ(old_cred, sgid.val);
    old_slim.euid = BPF_CORE_READ(old_cred, euid.val);
    old_slim.egid = BPF_CORE_READ(old_cred, egid.val);
    old_slim.fsuid = BPF_CORE_READ(old_cred, fsuid.val);
    old_slim.fsgid = BPF_CORE_READ(old_cred, fsgid.val);
    old_slim.user_ns = BPF_CORE_READ(userns_old, ns.inum);
    old_slim.securebits = BPF_CORE_READ(old_cred, securebits);

    old_slim.cap_inheritable = credcap_to_slimcap(&old_cred->cap_inheritable);
    old_slim.cap_permitted = credcap_to_slimcap(&old_cred->cap_permitted);
    old_slim.cap_effective = credcap_to_slimcap(&old_cred->cap_effective);
    old_slim.cap_bset = credcap_to_slimcap(&old_cred->cap_bset);
    old_slim.cap_ambient = credcap_to_slimcap(&old_cred->cap_ambient);

    // new credentials

    new_slim.uid = BPF_CORE_READ(new_cred, uid.val);
    new_slim.gid = BPF_CORE_READ(new_cred, gid.val);
    new_slim.suid = BPF_CORE_READ(new_cred, suid.val);
    new_slim.sgid = BPF_CORE_READ(new_cred, sgid.val);
    new_slim.euid = BPF_CORE_READ(new_cred, euid.val);
    new_slim.egid = BPF_CORE_READ(new_cred, egid.val);
    new_slim.fsuid = BPF_CORE_READ(new_cred, fsuid.val);
    new_slim.fsgid = BPF_CORE_READ(new_cred, fsgid.val);
    new_slim.user_ns = BPF_CORE_READ(userns_new, ns.inum);
    new_slim.securebits = BPF_CORE_READ(new_cred, securebits);

    new_slim.cap_inheritable = credcap_to_slimcap(&new_cred->cap_inheritable);
    new_slim.cap_permitted = credcap_to_slimcap(&new_cred->cap_permitted);
    new_slim.cap_effective = credcap_to_slimcap(&new_cred->cap_effective);
    new_slim.cap_bset = credcap_to_slimcap(&new_cred->cap_bset);
    new_slim.cap_ambient = credcap_to_slimcap(&new_cred->cap_ambient);

    save_to_submit_buf(&p.event->args_buf, (void *) &old_slim, sizeof(slim_cred_t), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &new_slim, sizeof(slim_cred_t), 1);

    // clang-format off
    if (
        (old_slim.uid != new_slim.uid)                          ||
        (old_slim.gid != new_slim.gid)                          ||
        (old_slim.suid != new_slim.suid)                        ||
        (old_slim.sgid != new_slim.sgid)                        ||
        (old_slim.euid != new_slim.euid)                        ||
        (old_slim.egid != new_slim.egid)                        ||
        (old_slim.fsuid != new_slim.fsuid)                      ||
        (old_slim.fsgid != new_slim.fsgid)                      ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable)  ||
        (old_slim.cap_permitted != new_slim.cap_permitted)      ||
        (old_slim.cap_effective != new_slim.cap_effective)      ||
        (old_slim.cap_bset != new_slim.cap_bset)                ||
        (old_slim.cap_ambient != new_slim.cap_ambient)
    ) {
        events_perf_submit(&p, 0);
    }
    // clang-format on

    return 0;
}

SEC("kprobe/switch_task_namespaces")
int BPF_KPROBE(trace_switch_task_namespaces)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SWITCH_TASK_NS))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct task_struct *task = (struct task_struct *) PT_REGS_PARM1(ctx);
    struct nsproxy *new = (struct nsproxy *) PT_REGS_PARM2(ctx);

    if (!new)
        return 0;

    pid_t pid = BPF_CORE_READ(task, pid);
    u32 old_mnt = p.event->context.task.mnt_id;
    u32 new_mnt = get_mnt_ns_id(new);
    u32 old_pid = get_task_pid_ns_for_children_id(task);
    u32 new_pid = get_pid_ns_for_children_id(new);
    u32 old_uts = get_task_uts_ns_id(task);
    u32 new_uts = get_uts_ns_id(new);
    u32 old_ipc = get_task_ipc_ns_id(task);
    u32 new_ipc = get_ipc_ns_id(new);
    u32 old_net = get_task_net_ns_id(task);
    u32 new_net = get_net_ns_id(new);
    u32 old_cgroup = get_task_cgroup_ns_id(task);
    u32 new_cgroup = get_cgroup_ns_id(new);

    save_to_submit_buf(&p.event->args_buf, (void *) &pid, sizeof(int), 0);

    if (old_mnt != new_mnt)
        save_to_submit_buf(&p.event->args_buf, (void *) &new_mnt, sizeof(u32), 1);
    if (old_pid != new_pid)
        save_to_submit_buf(&p.event->args_buf, (void *) &new_pid, sizeof(u32), 2);
    if (old_uts != new_uts)
        save_to_submit_buf(&p.event->args_buf, (void *) &new_uts, sizeof(u32), 3);
    if (old_ipc != new_ipc)
        save_to_submit_buf(&p.event->args_buf, (void *) &new_ipc, sizeof(u32), 4);
    if (old_net != new_net)
        save_to_submit_buf(&p.event->args_buf, (void *) &new_net, sizeof(u32), 5);
    if (old_cgroup != new_cgroup)
        save_to_submit_buf(&p.event->args_buf, (void *) &new_cgroup, sizeof(u32), 6);
    if (p.event->args_buf.argnum > 1)
        events_perf_submit(&p, 0);

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CAP_CAPABLE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(&p.event->args_buf, (void *) &cap, sizeof(int), 0);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_socket_create")
int BPF_KPROBE(trace_security_socket_create)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SOCKET_CREATE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    int family = (int) PT_REGS_PARM1(ctx);
    int type = (int) PT_REGS_PARM2(ctx);
    int protocol = (int) PT_REGS_PARM3(ctx);
    int kern = (int) PT_REGS_PARM4(ctx);

    save_to_submit_buf(&p.event->args_buf, (void *) &family, sizeof(int), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &type, sizeof(int), 1);
    save_to_submit_buf(&p.event->args_buf, (void *) &protocol, sizeof(int), 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &kern, sizeof(int), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(trace_security_inode_symlink)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_INODE_SYMLINK))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    const char *old_name = (const char *) PT_REGS_PARM3(ctx);

    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&p.event->args_buf, dentry_path, 0);
    save_str_to_buf(&p.event->args_buf, (void *) old_name, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/proc_create")
int BPF_KPROBE(trace_proc_create)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, PROC_CREATE))
        return 0;

    if (!evaluate_scope_filters((&p)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM4(ctx);

    save_str_to_buf(&p.event->args_buf, name, 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &proc_ops_addr, sizeof(u64), 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/debugfs_create_file")
int BPF_KPROBE(trace_debugfs_create_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, DEBUGFS_CREATE_FILE))
        return 0;

    if (!evaluate_scope_filters((&p)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    umode_t mode = (unsigned short) PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM3(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM5(ctx);

    save_str_to_buf(&p.event->args_buf, name, 0);
    save_str_to_buf(&p.event->args_buf, dentry_path, 1);
    save_to_submit_buf(&p.event->args_buf, &mode, sizeof(umode_t), 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &proc_ops_addr, sizeof(u64), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/debugfs_create_dir")
int BPF_KPROBE(trace_debugfs_create_dir)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, DEBUGFS_CREATE_DIR))
        return 0;

    if (!evaluate_scope_filters((&p)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&p.event->args_buf, name, 0);
    save_str_to_buf(&p.event->args_buf, dentry_path, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SOCKET_LISTEN))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int backlog = (int) PT_REGS_PARM2(ctx);

    // Load the arguments given to the listen syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced)
        return 0;

    switch (sys->id) {
        case SYSCALL_LISTEN:
            save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[0], sizeof(u32), 0);
            break;
#if defined(bpf_target_x86) // armhf makes use of SYSCALL_LISTEN
        case SYSCALL_SOCKETCALL:
            save_to_submit_buf(&p.event->args_buf, (void *) sys->args.args[1], sizeof(u32), 0);
            break;
#endif
        default:
            return 0;
    }

    save_sockaddr_to_buf(&p.event->args_buf, sock, 1);
    save_to_submit_buf(&p.event->args_buf, (void *) &backlog, sizeof(int), 2);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SOCKET_CONNECT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    u64 addr_len = PT_REGS_PARM3(ctx);

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    if (!sock)
        return 0;

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    if (!address)
        return 0;

    // Check if the socket type is supported.
    u32 type = BPF_CORE_READ(sock, type);
    switch (type) {
        // TODO: case SOCK_DCCP:
        case SOCK_DGRAM:
        case SOCK_SEQPACKET:
        case SOCK_STREAM:
            break;
        default:
            return 0;
    }

    // Check if the socket family is supported.
    sa_family_t sa_fam = get_sockaddr_family(address);
    switch (sa_fam) {
        case AF_INET:
        case AF_INET6:
        case AF_UNIX:
            break;
        default:
            return 0;
    }

    // Reduce line cols by having a few temp pointers.
    int (*stsb)(args_buffer_t *, void *, u32, u8) = save_to_submit_buf;
    void *args_buf = &p.event->args_buf;

    struct pt_regs *task_regs = get_current_task_pt_regs();
    int sockfd;
    void *arr_addr;
    switch (p.event->context.syscall) {
        case SYSCALL_CONNECT:
            sockfd = get_syscall_arg1(p.event->task, task_regs, false);
            stsb(args_buf, &sockfd, sizeof(int), 0);
            break;
        case SYSCALL_SOCKETCALL:
            arr_addr = (void *) get_syscall_arg2(p.event->task, task_regs, false);
            bpf_probe_read_user(
                &sockfd, sizeof(int), arr_addr); // fd is the first entry in the array
            stsb(args_buf, &sockfd, sizeof(int), 0);
            break;
    }

    // Save the socket type argument to the event.
    stsb(args_buf, &type, sizeof(u32), 1);

    bool need_workaround = false;

    // Save the sockaddr struct, depending on the family.
    size_t sockaddr_len = 0;
    switch (sa_fam) {
        case AF_INET:
            sockaddr_len = bpf_core_type_size(struct sockaddr_in);
            break;
        case AF_INET6:
            sockaddr_len = bpf_core_type_size(struct sockaddr_in6);
            break;
        case AF_UNIX:
            sockaddr_len = bpf_core_type_size(struct sockaddr_un);
            if (addr_len < sockaddr_len)
                need_workaround = true;

            break;
    }

#if defined(bpf_target_x86)
    if (need_workaround) {
        // Workaround for sockaddr_un struct length (issue: #1129).
        struct sockaddr_un sockaddr = {0};
        bpf_probe_read(&sockaddr, (u32) addr_len, (void *) address);
        // NOTE(nadav.str): stack allocated, so runtime core size check is avoided
        stsb(args_buf, (void *) &sockaddr, sizeof(struct sockaddr_un), 2);
    }
#endif

    // Save the sockaddr struct argument to the event.
    if (!need_workaround)
        stsb(args_buf, (void *) address, sockaddr_len, 2);

    // Submit the event.
    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SOCKET_ACCEPT))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct socket *new_sock = (struct socket *) PT_REGS_PARM2(ctx);

    struct pt_regs *task_regs = get_current_task_pt_regs();

    if (event_is_selected(SOCKET_ACCEPT, p.event->context.policies_version)) {
        args_t args = {};
        args.args[0] = (unsigned long) sock;
        args.args[1] = (unsigned long) new_sock;
        args.args[2] = get_syscall_arg1(p.event->task, task_regs, false); // sockfd
        save_args(&args, SOCKET_ACCEPT);
    }

    if (!evaluate_scope_filters(&p))
        return 0;

    // Load the arguments given to the accept syscall (which eventually invokes this function)
    if (!p.task_info->syscall_traced)
        return 0;

    int sockfd;
    switch (p.event->context.syscall) {
        case SYSCALL_ACCEPT:
        case SYSCALL_ACCEPT4:
            sockfd = get_syscall_arg1(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, (void *) &sockfd, sizeof(int), 0);
            break;
#if defined(bpf_target_x86) // armhf makes use of SYSCALL_ACCEPT/4
        case SYSCALL_SOCKETCALL:
            sockfd = get_syscall_arg2(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, (void *) &sockfd, sizeof(int), 0);
            break;
#endif
        default:
            return 0;
    }

    save_sockaddr_to_buf(&p.event->args_buf, sock, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SOCKET_BIND))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
#if defined(__TARGET_ARCH_x86) // TODO: issue: #1129
    uint addr_len = (uint) PT_REGS_PARM3(ctx);
#endif

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    struct pt_regs *task_regs = get_current_task_pt_regs();
    int sockfd;
    u64 sockfd_addr;
    switch (p.event->context.syscall) {
        case SYSCALL_BIND:
            sockfd = get_syscall_arg1(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, (void *) &sockfd, sizeof(u32), 0);
            break;
#if defined(bpf_target_x86) // armhf makes use of SYSCALL_BIND
        case SYSCALL_SOCKETCALL:
            sockfd_addr = get_syscall_arg2(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, (void *) sockfd_addr, sizeof(u32), 0);
            break;
#endif
        default:
            return 0;
    }

    u16 protocol = get_sock_protocol(sk);
    net_id_t connect_id = {0};
    connect_id.protocol = protocol;

    if (sa_fam == AF_INET) {
        save_to_submit_buf(
            &p.event->args_buf, (void *) address, bpf_core_type_size(struct sockaddr_in), 1);

        struct sockaddr_in *addr = (struct sockaddr_in *) address;

        if (protocol == IPPROTO_UDP && BPF_CORE_READ(addr, sin_port)) {
            connect_id.address.s6_addr32[3] = BPF_CORE_READ(addr, sin_addr).s_addr;
            connect_id.address.s6_addr16[5] = 0xffff;
            connect_id.port = BPF_CORE_READ(addr, sin_port);
        }
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(
            &p.event->args_buf, (void *) address, bpf_core_type_size(struct sockaddr_in6), 1);

        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) address;

        if (protocol == IPPROTO_UDP && BPF_CORE_READ(addr, sin6_port)) {
            connect_id.address = BPF_CORE_READ(addr, sin6_addr);
            connect_id.port = BPF_CORE_READ(addr, sin6_port);
        }
    } else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            // NOTE(nadav.str): stack allocated, so runtime core size check is avoided
            bpf_probe_read(&sockaddr, addr_len, (void *) address);
            save_to_submit_buf(
                &p.event->args_buf, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(
                &p.event->args_buf, (void *) address, bpf_core_type_size(struct sockaddr_un), 1);
    }

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_socket_setsockopt")
int BPF_KPROBE(trace_security_socket_setsockopt)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SOCKET_SETSOCKOPT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int level = (int) PT_REGS_PARM2(ctx);
    int optname = (int) PT_REGS_PARM3(ctx);

    struct pt_regs *task_regs = get_current_task_pt_regs();
    int sockfd;
    u64 sockfd_addr;
    switch (p.event->context.syscall) {
        case SYSCALL_SETSOCKOPT:
            sockfd = get_syscall_arg1(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, (void *) &sockfd, sizeof(u32), 0);
            break;
#if defined(bpf_target_x86) // armhf makes use of SYSCALL_SETSOCKOPT
        case SYSCALL_SOCKETCALL:
            sockfd_addr = get_syscall_arg2(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, (void *) sockfd_addr, sizeof(u32), 0);
            break;
#endif
        default:
            return 0;
    }

    save_to_submit_buf(&p.event->args_buf, (void *) &level, sizeof(int), 1);
    save_to_submit_buf(&p.event->args_buf, (void *) &optname, sizeof(int), 2);
    save_sockaddr_to_buf(&p.event->args_buf, sock, 3);

    return events_perf_submit(&p, 0);
}

enum bin_type_e
{
    SEND_VFS_WRITE = 1,
    SEND_MPROTECT,
    SEND_KERNEL_MODULE,
    SEND_BPF_OBJECT,
    SEND_VFS_READ
};

statfunc u32 tail_call_send_bin(void *ctx, program_data_t *p, bin_args_t *bin_args, int tail_call)
{
    if (p->event->args_buf.offset < ARGS_BUF_SIZE - sizeof(bin_args_t)) {
        bpf_probe_read_kernel(
            &(p->event->args_buf.args[p->event->args_buf.offset]), sizeof(bin_args_t), bin_args);
        if (tail_call == TAIL_SEND_BIN)
            bpf_tail_call(ctx, &prog_array, tail_call);
        else if (tail_call == TAIL_SEND_BIN_TP)
            bpf_tail_call(ctx, &prog_array_tp, tail_call);
    }

    return 0;
}

statfunc u32 send_bin_helper(void *ctx, void *prog_array, int tail_call)
{
    // Note: sending the data to the userspace have the following constraints:
    //
    // 1. We need a buffer that we know it's exact size
    //    (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data
    //    can be overridden if userspace doesn't consume
    //    it fast enough

    int i = 0;
    unsigned int chunk_size;
    u32 zero = 0;

    event_data_t *event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (!event || (event->args_buf.offset > ARGS_BUF_SIZE - sizeof(bin_args_t)))
        return 0;

    bin_args_t *bin_args = (bin_args_t *) &(event->args_buf.args[event->args_buf.offset]);

    if (bin_args->full_size <= 0) {
        // If there are more vector elements, continue to the next one
        bin_args->iov_idx++;
        if (bin_args->iov_idx < bin_args->iov_len) {
            // Handle the rest of write recursively
            bin_args->start_off += bin_args->full_size;
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
            bin_args->ptr = io_vec.iov_base;
            bin_args->full_size = io_vec.iov_len;
            bpf_tail_call(ctx, prog_array, tail_call);
        }
        return 0;
    }

    buf_t *file_buf_p = get_buf(FILE_BUF_IDX);
    if (file_buf_p == NULL)
        return 0;

#define F_SEND_TYPE  0
#define F_CGROUP_ID  (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF   (F_CGROUP_ID + sizeof(u64))
#define F_SZ_OFF     (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF    (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF  (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE (MAX_PERCPU_BUFSIZE >> 1)

    bpf_probe_read_kernel((void **) &(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args->type);

    u64 cgroup_id = event->context.task.cgroup_id;
    bpf_probe_read_kernel((void **) &(file_buf_p->buf[F_CGROUP_ID]), sizeof(u64), &cgroup_id);

    // Save metadata to be used in filename
    bpf_probe_read_kernel(
        (void **) &(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args->metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read_kernel(
        (void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = bin_args->full_size / F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

// Handle full chunks in loop
#pragma unroll
    for (i = 0; i < MAX_BIN_CHUNKS; i++) {
        // Dummy instruction, as break instruction can't be first with unroll optimization
        chunk_size = F_CHUNK_SIZE;

        if (i == full_chunk_num)
            break;

        // Save binary chunk and file position of write
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);
        bpf_probe_read_user((void **) &(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, bin_args->ptr);
        bin_args->ptr += F_CHUNK_SIZE;
        bin_args->start_off += F_CHUNK_SIZE;

        bpf_perf_event_output(
            ctx, &file_writes, BPF_F_CURRENT_CPU, data, F_CHUNK_OFF + F_CHUNK_SIZE);
    }

    chunk_size = bin_args->full_size - i * F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        // Handle the rest of write recursively
        bin_args->full_size = chunk_size;
        bpf_tail_call(ctx, prog_array, tail_call);
        return 0;
    }

    if (chunk_size) {
        // Save last chunk
        chunk_size = chunk_size & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
        bpf_probe_read_user((void **) &(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

        // Satisfy validator by setting buffer bounds
        int size = (F_CHUNK_OFF + chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
        bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, size);
    }

    // We finished writing an element of the vector - continue to next element
    bin_args->iov_idx++;
    if (bin_args->iov_idx < bin_args->iov_len) {
        // Handle the rest of write recursively
        bin_args->start_off += bin_args->full_size;
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
        bin_args->ptr = io_vec.iov_base;
        bin_args->full_size = io_vec.iov_len;
        bpf_tail_call(ctx, prog_array, tail_call);
    }

    return 0;
}

SEC("kprobe/send_bin")
int BPF_KPROBE(send_bin)
{
    return send_bin_helper(ctx, &prog_array, TAIL_SEND_BIN);
}

SEC("raw_tracepoint/send_bin_tp")
int send_bin_tp(void *ctx)
{
    return send_bin_helper(ctx, &prog_array_tp, TAIL_SEND_BIN_TP);
}

/** do_file_io_operation - generic file IO (read and write) event creator.
 *
 * @ctx:            the state of the registers prior the hook.
 * @event_id:       the ID of the event to be created.
 * @tail_call_id:   the ID of the tail call to be called before function return.
 * @is_read:        true if the operation is read. False if write.
 * @is_buf:         true if the non-file side of the operation is a buffer. False if io_vector.
 */
statfunc int
do_file_io_operation(struct pt_regs *ctx, u32 event_id, u32 tail_call_id, bool is_read, bool is_buf)
{
    args_t saved_args;
    if (load_args(&saved_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }
    // We shouldn't call del_args(event_id) here as the arguments are also used by the tail call

    program_data_t p = {};
    if (!init_program_data(&p, ctx, event_id))
        goto out;

    if (!evaluate_scope_filters(&p))
        goto tail;

    loff_t start_pos;
    io_data_t io_data;
    file_info_t file_info;

    struct file *file = (struct file *) saved_args.args[0];
    file_info.pathname_p = get_path_str_cached(file);

    io_data.is_buf = is_buf;
    io_data.ptr = (void *) saved_args.args[1];
    io_data.len = (unsigned long) saved_args.args[2];
    loff_t *pos = (loff_t *) saved_args.args[3];

    // Extract device id, inode number, and pos (offset)
    file_info.id.device = get_dev_from_file(file);
    file_info.id.inode = get_inode_nr_from_file(file);
    bpf_probe_read_kernel(&start_pos, sizeof(off_t), pos);

    u32 io_bytes_amount = PT_REGS_RC(ctx);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= io_bytes_amount;

    save_str_to_buf(&p.event->args_buf, file_info.pathname_p, 0);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.device, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.inode, sizeof(unsigned long), 2);
    save_to_submit_buf(&p.event->args_buf, &io_data.len, sizeof(unsigned long), 3);
    save_to_submit_buf(&p.event->args_buf, &start_pos, sizeof(off_t), 4);

    // Submit io event
    events_perf_submit(&p, PT_REGS_RC(ctx));

tail:
    bpf_tail_call(ctx, &prog_array, tail_call_id);
out:
    del_args(event_id);

    return 0;
}

statfunc void
extract_vfs_ret_io_data(struct pt_regs *ctx, args_t *saved_args, io_data_t *io_data, bool is_buf)
{
    io_data->is_buf = is_buf;
    if (is_buf) {
        io_data->ptr = (void *) saved_args->args[1]; // pointer to buf
        io_data->len = (size_t) PT_REGS_RC(ctx);     // number of bytes written to buf
    } else {
        io_data->ptr = (struct iovec *) saved_args->args[1]; // pointer to iovec array
        io_data->len = saved_args->args[2];                  // number of iovec elements in array
    }
}

// Filter capture of file writes according to path prefix, type and fd.
statfunc bool
filter_file_write_capture(program_data_t *p, struct file *file, io_data_t io_data, off_t start_pos)
{
    return filter_file_path(p->ctx, &file_write_path_filter, file) ||
           filter_file_type(p->ctx,
                            &file_type_filter,
                            CAPTURE_WRITE_TYPE_FILTER_IDX,
                            file,
                            io_data,
                            start_pos) ||
           filter_file_fd(p->ctx, &file_type_filter, CAPTURE_WRITE_TYPE_FILTER_IDX, file);
}

// Capture file write
// Will only capture if:
// 1. File write capture was configured
// 2. File matches the filters given
statfunc int capture_file_write(struct pt_regs *ctx, u32 event_id, bool is_buf)
{
    args_t saved_args;
    io_data_t io_data;

    if (load_args(&saved_args, event_id) != 0)
        return 0;
    del_args(event_id);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    if ((p.config->options & OPT_CAPTURE_FILES_WRITE) == 0)
        return 0;

    extract_vfs_ret_io_data(ctx, &saved_args, &io_data, is_buf);
    struct file *file = (struct file *) saved_args.args[0];
    loff_t *pos = (loff_t *) saved_args.args[3];
    size_t written_bytes = PT_REGS_RC(ctx);

    off_t start_pos;
    bpf_probe_read_kernel(&start_pos, sizeof(off_t), pos);
    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= written_bytes;

    if (filter_file_write_capture(&p, file, io_data, start_pos)) {
        // There is a filter, but no match
        return 0;
    }
    // No filter was given, or filter match - continue

    // Because we don't pass the file path in the capture map, we can't do path checks in user mode.
    // We don't want to pass the PID for most file writes, because we want to save writes according
    // to the inode-device only. In the case of writes to /dev/null, we want to pass the PID because
    // otherwise the capture will overwrite itself.
    int pid = 0;
    void *path_buf = get_path_str_cached(file);
    if (path_buf != NULL && strncmp("/dev/null", (char *) path_buf, 10) == 0) {
        pid = p.event->context.task.pid;
    }

    bin_args_t bin_args = {};
    fill_vfs_file_bin_args(SEND_VFS_WRITE, file, pos, io_data, PT_REGS_RC(ctx), pid, &bin_args);

    // Send file data
    tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
    return 0;
}

// Filter capture of file reads according to path prefix, type and fd.
statfunc bool
filter_file_read_capture(program_data_t *p, struct file *file, io_data_t io_data, off_t start_pos)
{
    return filter_file_path(p->ctx, &file_read_path_filter, file) ||
           filter_file_type(
               p->ctx, &file_type_filter, CAPTURE_READ_TYPE_FILTER_IDX, file, io_data, start_pos) ||
           filter_file_fd(p->ctx, &file_type_filter, CAPTURE_READ_TYPE_FILTER_IDX, file);
}

statfunc int capture_file_read(struct pt_regs *ctx, u32 event_id, bool is_buf)
{
    args_t saved_args;
    io_data_t io_data;

    if (load_args(&saved_args, event_id) != 0)
        return 0;
    del_args(event_id);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    if ((p.config->options & OPT_CAPTURE_FILES_READ) == 0)
        return 0;

    extract_vfs_ret_io_data(ctx, &saved_args, &io_data, is_buf);
    struct file *file = (struct file *) saved_args.args[0];
    loff_t *pos = (loff_t *) saved_args.args[3];
    size_t read_bytes = PT_REGS_RC(ctx);

    off_t start_pos;
    bpf_probe_read_kernel(&start_pos, sizeof(off_t), pos);
    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= read_bytes;

    if (filter_file_read_capture(&p, file, io_data, start_pos)) {
        // There is a filter, but no match
        return 0;
    }
    // No filter was given, or filter match - continue

    bin_args_t bin_args = {};
    u64 id = bpf_get_current_pid_tgid();
    fill_vfs_file_bin_args(SEND_VFS_READ, file, pos, io_data, PT_REGS_RC(ctx), 0, &bin_args);

    // Send file data
    tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
    return 0;
}

SEC("kprobe/vfs_write")
TRACE_ENT_FUNC(vfs_write, VFS_WRITE);

SEC("kretprobe/vfs_write")
int BPF_KPROBE(trace_ret_vfs_write)
{
    return do_file_io_operation(ctx, VFS_WRITE, TAIL_VFS_WRITE, false, true);
}

SEC("kretprobe/vfs_write_tail")
int BPF_KPROBE(trace_ret_vfs_write_tail)
{
    return capture_file_write(ctx, VFS_WRITE, true);
}

SEC("kprobe/vfs_writev")
TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(trace_ret_vfs_writev)
{
    return do_file_io_operation(ctx, VFS_WRITEV, TAIL_VFS_WRITEV, false, false);
}

SEC("kretprobe/vfs_writev_tail")
int BPF_KPROBE(trace_ret_vfs_writev_tail)
{
    return capture_file_write(ctx, VFS_WRITEV, false);
}

SEC("kprobe/__kernel_write")
TRACE_ENT_FUNC(kernel_write, __KERNEL_WRITE);

SEC("kretprobe/__kernel_write")
int BPF_KPROBE(trace_ret_kernel_write)
{
    return do_file_io_operation(ctx, __KERNEL_WRITE, TAIL_KERNEL_WRITE, false, true);
}

SEC("kretprobe/__kernel_write_tail")
int BPF_KPROBE(trace_ret_kernel_write_tail)
{
    return capture_file_write(ctx, __KERNEL_WRITE, true);
}

SEC("kprobe/vfs_read")
TRACE_ENT_FUNC(vfs_read, VFS_READ);

SEC("kretprobe/vfs_read")
int BPF_KPROBE(trace_ret_vfs_read)
{
    return do_file_io_operation(ctx, VFS_READ, TAIL_VFS_READ, true, true);
}

SEC("kretprobe/vfs_read_tail")
int BPF_KPROBE(trace_ret_vfs_read_tail)
{
    return capture_file_read(ctx, VFS_READ, true);
}

SEC("kprobe/vfs_readv")
TRACE_ENT_FUNC(vfs_readv, VFS_READV);

SEC("kretprobe/vfs_readv")
int BPF_KPROBE(trace_ret_vfs_readv)
{
    return do_file_io_operation(ctx, VFS_READV, TAIL_VFS_READV, true, false);
}

SEC("kretprobe/vfs_readv_tail")
int BPF_KPROBE(trace_ret_vfs_readv_tail)
{
    return capture_file_read(ctx, VFS_READV, false);
}

statfunc int do_vfs_write_magic_enter(struct pt_regs *ctx)
{
    loff_t start_pos;
    loff_t *pos = (loff_t *) PT_REGS_PARM4(ctx);
    bpf_probe_read_kernel(&start_pos, sizeof(off_t), pos);
    if (start_pos != 0)
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    unsigned short i_mode = get_inode_mode_from_file(file);
    if ((i_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    args_t args = {};
    args.args[0] = PT_REGS_PARM1(ctx);
    args.args[1] = PT_REGS_PARM2(ctx);
    args.args[2] = PT_REGS_PARM3(ctx);
    args.args[3] = PT_REGS_PARM4(ctx);
    args.args[4] = PT_REGS_PARM5(ctx);
    args.args[5] = PT_REGS_PARM6(ctx);

    return save_args(&args, MAGIC_WRITE);
}

statfunc int do_vfs_write_magic_return(struct pt_regs *ctx, bool is_buf)
{
    args_t saved_args;
    if (load_args(&saved_args, MAGIC_WRITE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(MAGIC_WRITE);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, MAGIC_WRITE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    u32 bytes_written = PT_REGS_RC(ctx);
    if (bytes_written == 0)
        return 0;

    io_data_t io_data;
    file_info_t file_info;

    struct file *file = (struct file *) saved_args.args[0];
    file_info.pathname_p = get_path_str_cached(file);

    io_data.is_buf = is_buf;
    io_data.ptr = (void *) saved_args.args[1];
    io_data.len = (unsigned long) saved_args.args[2];

    // Extract device id, inode number, and pos (offset)
    file_info.id.device = get_dev_from_file(file);
    file_info.id.inode = get_inode_nr_from_file(file);

    u32 header_bytes = FILE_MAGIC_HDR_SIZE;
    if (header_bytes > bytes_written)
        header_bytes = bytes_written;

    u8 header[FILE_MAGIC_HDR_SIZE];
    __builtin_memset(&header, 0, sizeof(header));

    save_str_to_buf(&(p.event->args_buf), file_info.pathname_p, 0);

    fill_file_header(header, io_data);

    save_bytes_to_buf(&(p.event->args_buf), header, header_bytes, 1);
    save_to_submit_buf(&(p.event->args_buf), &file_info.id.device, sizeof(dev_t), 2);
    save_to_submit_buf(&(p.event->args_buf), &file_info.id.inode, sizeof(unsigned long), 3);

    if (!evaluate_data_filters(&p, 0))
        return 0;

    // Submit magic_write event
    return events_perf_submit(&p, bytes_written);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_magic_enter)
{
    return do_vfs_write_magic_enter(ctx);
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(vfs_writev_magic_enter)
{
    return do_vfs_write_magic_enter(ctx);
}

SEC("kprobe/__kernel_write")
int BPF_KPROBE(kernel_write_magic_enter)
{
    return do_vfs_write_magic_enter(ctx);
}

SEC("kretprobe/vfs_write")
int BPF_KPROBE(vfs_write_magic_return)
{
    return do_vfs_write_magic_return(ctx, true);
}

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(vfs_writev_magic_return)
{
    return do_vfs_write_magic_return(ctx, false);
}

SEC("kretprobe/__kernel_write")
int BPF_KPROBE(kernel_write_magic_return)
{
    return do_vfs_write_magic_return(ctx, true);
}

// Used macro because of problem with verifier in NONCORE kinetic519
#define submit_mem_prot_alert_event(event, alert, addr, len, prot, previous_prot, file_info)       \
    {                                                                                              \
        save_to_submit_buf(event, &alert, sizeof(u32), 0);                                         \
        save_to_submit_buf(event, &addr, sizeof(void *), 1);                                       \
        save_to_submit_buf(event, &len, sizeof(size_t), 2);                                        \
        save_to_submit_buf(event, &prot, sizeof(int), 3);                                          \
        save_to_submit_buf(event, &previous_prot, sizeof(int), 4);                                 \
        if (file_info.pathname_p != NULL) {                                                        \
            save_str_to_buf(event, file_info.pathname_p, 5);                                       \
            save_to_submit_buf(event, &file_info.id.device, sizeof(dev_t), 6);                     \
            save_to_submit_buf(event, &file_info.id.inode, sizeof(unsigned long), 7);              \
            save_to_submit_buf(event, &file_info.id.ctime, sizeof(u64), 8);                        \
        }                                                                                          \
        events_perf_submit(&p, 0);                                                                 \
    }

SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_alert)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, MEM_PROT_ALERT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    if (p.event->context.syscall != SYSCALL_MMAP)
        return 0;

    struct pt_regs *task_regs = get_current_task_pt_regs();
    int prot = get_syscall_arg3(p.event->task, task_regs, false);
    if ((prot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)) {
        u32 alert = ALERT_MMAP_W_X;
        void *addr = (void *) get_syscall_arg1(p.event->task, task_regs, false);
        size_t len = get_syscall_arg2(p.event->task, task_regs, false);
        int fd = get_syscall_arg5(p.event->task, task_regs, false);
        int prev_prot = 0;
        file_info_t file_info = {.pathname_p = NULL};
        if (fd >= 0) {
            struct file *file = get_struct_file_from_fd(fd);
            file_info = get_file_info(file);
        }
        submit_mem_prot_alert_event(
            &p.event->args_buf, alert, addr, len, prot, prev_prot, file_info);
    }

    return 0;
}

SEC("kprobe/do_mmap")
TRACE_ENT_FUNC(do_mmap, DO_MMAP)

SEC("kretprobe/do_mmap")
int BPF_KPROBE(trace_ret_do_mmap)
{
    args_t saved_args;
    if (load_args(&saved_args, DO_MMAP) != 0) {
        // missed entry or not traced
        return 0;
    }

    program_data_t p = {};
    if (!init_program_data(&p, ctx, DO_MMAP))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    dev_t s_dev;
    unsigned long inode_nr;
    void *file_path;
    u64 ctime;
    unsigned int flags;

    struct file *file = (struct file *) saved_args.args[0];
    if (file != NULL) {
        s_dev = get_dev_from_file(file);
        inode_nr = get_inode_nr_from_file(file);
        file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
        ctime = get_ctime_nanosec_from_file(file);
    }
    unsigned long len = (unsigned long) saved_args.args[2];
    unsigned long prot = (unsigned long) saved_args.args[3];
    unsigned long mmap_flags = (unsigned long) saved_args.args[4];
    unsigned long pgoff = (unsigned long) saved_args.args[5];
    unsigned long addr = (unsigned long) PT_REGS_RC(ctx);

    save_to_submit_buf(&p.event->args_buf, &addr, sizeof(void *), 0);
    if (file != NULL) {
        save_str_to_buf(&p.event->args_buf, file_path, 1);
        save_to_submit_buf(&p.event->args_buf, &flags, sizeof(unsigned int), 2);
        save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 3);
        save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 4);
        save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 5);
    }
    save_to_submit_buf(&p.event->args_buf, &pgoff, sizeof(unsigned long), 6);
    save_to_submit_buf(&p.event->args_buf, &len, sizeof(unsigned long), 7);
    save_to_submit_buf(&p.event->args_buf, &prot, sizeof(unsigned long), 8);
    save_to_submit_buf(&p.event->args_buf, &mmap_flags, sizeof(unsigned long), 9);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(trace_security_mmap_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SHARED_OBJECT_LOADED))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == 0)
        return 0;
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = NULL;
    u64 ctime = get_ctime_nanosec_from_file(file);
    unsigned long prot = (unsigned long) PT_REGS_PARM2(ctx);
    unsigned long mmap_flags = (unsigned long) PT_REGS_PARM3(ctx);

    if (evaluate_scope_filters(&p) && (prot & VM_EXEC) == VM_EXEC &&
        p.event->context.syscall == SYSCALL_MMAP) {
        file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));

        save_str_to_buf(&p.event->args_buf, file_path, 0);
        save_to_submit_buf(&p.event->args_buf,
                           (void *) __builtin_preserve_access_index(&file->f_flags),
                           sizeof(int),
                           1);
        save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 2);
        save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 3);
        save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);

        events_perf_submit(&p, 0);
    }

    if (!reset_event(p.event, SECURITY_MMAP_FILE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    if (!file_path)
        file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));

    save_str_to_buf(&p.event->args_buf, file_path, 0);
    save_to_submit_buf(&p.event->args_buf,
                       (void *) __builtin_preserve_access_index(&file->f_flags),
                       sizeof(int),
                       1);
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);
    save_to_submit_buf(&p.event->args_buf, &prot, sizeof(unsigned long), 5);
    save_to_submit_buf(&p.event->args_buf, &mmap_flags, sizeof(unsigned long), 6);

    if (!evaluate_data_filters(&p, 0))
        return 0;

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_security_file_mprotect)
{
    bin_args_t bin_args = {};
    file_info_t file_info;
    file_info.id.inode = 0;

    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_FILE_MPROTECT))
        return 0;

    if (p.event->context.syscall != SYSCALL_MPROTECT &&
        p.event->context.syscall != SYSCALL_PKEY_MPROTECT)
        return 0;

    struct vm_area_struct *vma = (struct vm_area_struct *) PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);
    unsigned long prev_prot = get_vma_flags(vma);
    struct file *file = (struct file *) BPF_CORE_READ(vma, vm_file);

    struct pt_regs *task_regs = get_current_task_pt_regs();
    void *addr = (void *) get_syscall_arg1(p.event->task, task_regs, false);
    size_t len = get_syscall_arg2(p.event->task, task_regs, false);

    if (evaluate_scope_filters(&p)) {
        file_info = get_file_info(file);

        save_str_to_buf(&p.event->args_buf, file_info.pathname_p, 0);
        save_to_submit_buf(&p.event->args_buf, &reqprot, sizeof(int), 1);
        save_to_submit_buf(&p.event->args_buf, &file_info.id.ctime, sizeof(u64), 2);
        save_to_submit_buf(&p.event->args_buf, &prev_prot, sizeof(int), 3);
        save_to_submit_buf(&p.event->args_buf, &addr, sizeof(void *), 4);
        save_to_submit_buf(&p.event->args_buf, &len, sizeof(size_t), 5);

        if (p.event->context.syscall == SYSCALL_PKEY_MPROTECT) {
            int pkey = get_syscall_arg4(p.event->task, task_regs, false);
            save_to_submit_buf(&p.event->args_buf, &pkey, sizeof(int), 6);
        }

        events_perf_submit(&p, 0);
    }

    if (!reset_event(p.event, MEM_PROT_ALERT))
        return 0;

    if (!evaluate_scope_filters(&p) && !(p.config->options & OPT_EXTRACT_DYN_CODE))
        return 0;

    // only get file info if it wasn't already initialized
    if (!file_info.id.inode)
        file_info = get_file_info(file);

    if (addr <= 0)
        return 0;

    // If length is 0, the current page permissions are changed
    if (len == 0)
        len = PAGE_SIZE;

    u32 alert;
    bool should_alert = false;
    bool should_extract_code = false;

    if ((!(prev_prot & VM_EXEC)) && (reqprot & VM_EXEC)) {
        alert = ALERT_MPROT_X_ADD;
        should_alert = true;
    }

    if ((prev_prot & VM_EXEC) && !(prev_prot & VM_WRITE) &&
        ((reqprot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC))) {
        alert = ALERT_MPROT_W_ADD;
        should_alert = true;
    }

    if ((prev_prot & VM_WRITE) && (reqprot & VM_EXEC) && !(reqprot & VM_WRITE)) {
        alert = ALERT_MPROT_W_REM;
        should_alert = true;

        if (p.config->options & OPT_EXTRACT_DYN_CODE)
            should_extract_code = true;
    }

    if (should_alert && policies_matched(p.event))
        submit_mem_prot_alert_event(
            &p.event->args_buf, alert, addr, len, reqprot, prev_prot, file_info);

    if (should_extract_code) {
        u32 pid = p.event->context.task.host_pid;
        bin_args.type = SEND_MPROTECT;
        bpf_probe_read_kernel(bin_args.metadata, sizeof(u64), &p.event->context.ts);
        bpf_probe_read_kernel(&bin_args.metadata[8], 4, &pid);
        bin_args.ptr = (char *) addr;
        bin_args.start_off = 0;
        bin_args.full_size = len;

        tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
    }

    return 0;
}

SEC("raw_tracepoint/sys_init_module")
int syscall__init_module(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced)
        return -1;

    bin_args_t bin_args = {};

    u32 pid = p.event->context.task.host_pid;
    u64 dummy = 0;
    void *addr = (void *) sys->args.args[0];
    unsigned long len = (unsigned long) sys->args.args[1];

    if (p.config->options & OPT_CAPTURE_MODULES) {
        bin_args.type = SEND_KERNEL_MODULE;
        bpf_probe_read_kernel(bin_args.metadata, 4, &dummy);
        bpf_probe_read_kernel(&bin_args.metadata[4], 8, &dummy);
        bpf_probe_read_kernel(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read_kernel(&bin_args.metadata[16], 8, &len);
        bin_args.ptr = (char *) addr;
        bin_args.start_off = 0;
        bin_args.full_size = (unsigned int) len;

        tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN_TP);
    }
    return 0;
}

statfunc int do_check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd)
{
    if (cmd == BPF_LINK_CREATE) {
        u32 prog_fd = BPF_CORE_READ(attr, link_create.prog_fd);
        u32 perf_fd = BPF_CORE_READ(attr, link_create.target_fd);

        struct file *bpf_prog_file = get_struct_file_from_fd(prog_fd);
        struct file *perf_event_file = get_struct_file_from_fd(perf_fd);

        send_bpf_perf_attach(p, bpf_prog_file, perf_event_file);
    }

    return 0;
}

statfunc int check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd)
{
    // BPF_LINK_CREATE command was only introduced in kernel 5.7.
    // nothing to check for kernels < 5.7.

    if (bpf_core_field_exists(attr->link_create)) {
        do_check_bpf_link(p, attr, cmd);
    }

    return 0;
}

SEC("kprobe/security_bpf")
int BPF_KPROBE(trace_security_bpf)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPF))
        return 0;

    int cmd = (int) PT_REGS_PARM1(ctx);

    // send security_bpf event if filters match
    if (evaluate_scope_filters(&p)) {
        save_to_submit_buf(&p.event->args_buf, (void *) &cmd, sizeof(int), 0);
        events_perf_submit(&p, 0);
    }

    if (!reset_event(p.event, BPF_ATTACH))
        return 0;

    union bpf_attr *attr = (union bpf_attr *) PT_REGS_PARM2(ctx);

    // send bpf_attach event if filters match
    if (evaluate_scope_filters(&p))
        check_bpf_link(&p, attr, cmd);

    // Capture BPF object loaded
    if (cmd == BPF_PROG_LOAD && p.config->options & OPT_CAPTURE_BPF) {
        bin_args_t bin_args = {};
        u32 pid = p.task_info->context.host_pid;

        u32 insn_cnt = get_attr_insn_cnt(attr);
        const struct bpf_insn *insns = get_attr_insns(attr);
        unsigned int insn_size = (unsigned int) (sizeof(struct bpf_insn) * insn_cnt);

        bin_args.type = SEND_BPF_OBJECT;
        char prog_name[16] = {0};
        long sz = bpf_probe_read_kernel_str(prog_name, 16, attr->prog_name);
        if (sz > 0) {
            sz = bpf_probe_read_kernel_str(bin_args.metadata, sz, prog_name);
        }

        u32 rand = bpf_get_prandom_u32();
        bpf_probe_read_kernel(&bin_args.metadata[16], 4, &rand);
        bpf_probe_read_kernel(&bin_args.metadata[20], 4, &pid);
        bpf_probe_read_kernel(&bin_args.metadata[24], 4, &insn_size);
        bin_args.ptr = (char *) insns;
        bin_args.start_off = 0;
        bin_args.full_size = insn_size;

        tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
    }
    return 0;
}

// arm_kprobe can't be hooked in arm64 architecture, use enable logic instead

statfunc int arm_kprobe_handler(struct pt_regs *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, KPROBE_ATTACH) != 0) {
        return 0;
    }
    del_args(KPROBE_ATTACH);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, KPROBE_ATTACH))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct kprobe *kp = (struct kprobe *) saved_args.args[0];
    unsigned int retcode = PT_REGS_RC(ctx);

    if (retcode)
        return 0; // register_kprobe() failed

    char *symbol_name = (char *) BPF_CORE_READ(kp, symbol_name);
    u64 pre_handler = (u64) BPF_CORE_READ(kp, pre_handler);
    u64 post_handler = (u64) BPF_CORE_READ(kp, post_handler);

    save_str_to_buf(&p.event->args_buf, (void *) symbol_name, 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &pre_handler, sizeof(u64), 1);
    save_to_submit_buf(&p.event->args_buf, (void *) &post_handler, sizeof(u64), 2);

    return events_perf_submit(&p, 0);
}

// register_kprobe and enable_kprobe have same execution path, and both call
// arm_kprobe, which is the function we are interested in. Nevertheless, there
// is also another function, register_aggr_kprobes, that might be able to call
// arm_kprobe so, instead of hooking into enable_kprobe, we hook into
// register_kprobe covering all execution paths.

SEC("kprobe/register_kprobe")
TRACE_ENT_FUNC(register_kprobe, KPROBE_ATTACH);

SEC("kretprobe/register_kprobe")
int BPF_KPROBE(trace_ret_register_kprobe)
{
    return arm_kprobe_handler(ctx);
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(trace_security_bpf_map)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPF_MAP))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct bpf_map *map = (struct bpf_map *) PT_REGS_PARM1(ctx);

    // 1st argument == map_id (u32)
    save_to_submit_buf(
        &p.event->args_buf, (void *) __builtin_preserve_access_index(&map->id), sizeof(int), 0);
    // 2nd argument == map_name (const char *)
    save_str_to_buf(&p.event->args_buf, (void *) __builtin_preserve_access_index(&map->name), 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(trace_security_bpf_prog)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPF_PROG))
        return 0;

    struct bpf_prog *prog = (struct bpf_prog *) PT_REGS_PARM1(ctx);
    struct bpf_prog_aux *prog_aux = BPF_CORE_READ(prog, aux);
    u32 prog_id = BPF_CORE_READ(prog_aux, id);

    // In some systems, the 'check_map_func_compatibility' and 'check_helper_call' symbols are not
    // available. For these cases, the temporary map 'bpf_attach_tmp_map' will not hold any
    // information about the used helpers in the prog. nevertheless, we always want to output the
    // 'bpf_attach' event to the user, so using zero values
    bpf_used_helpers_t val = {0};

    // if there is a value, use it
    bpf_used_helpers_t *existing_val;
    existing_val = bpf_map_lookup_elem(&bpf_attach_tmp_map, &p.event->context.task.host_tid);
    if (existing_val != NULL) {
        __builtin_memcpy(&val.helpers, &existing_val->helpers, sizeof(bpf_used_helpers_t));
    }

    bpf_map_delete_elem(&bpf_attach_tmp_map, &p.event->context.task.host_tid);

    if (event_is_selected(BPF_ATTACH, p.event->context.policies_version))
        bpf_map_update_elem(&bpf_attach_map, &prog_id, &val, BPF_ANY);

    if (!evaluate_scope_filters(&p))
        return 0;

    bool is_load = false;
    void **aux_ptr = bpf_map_lookup_elem(&bpf_prog_load_map, &p.event->context.task.host_tid);
    if (aux_ptr != NULL) {
        if (*aux_ptr == (void *) prog_aux)
            is_load = true;

        bpf_map_delete_elem(&bpf_prog_load_map, &p.event->context.task.host_tid);
    }

    int prog_type = BPF_CORE_READ(prog, type);

    char prog_name[BPF_OBJ_NAME_LEN];
    bpf_probe_read_kernel_str(&prog_name, BPF_OBJ_NAME_LEN, prog_aux->name);

    save_to_submit_buf(&p.event->args_buf, &prog_type, sizeof(int), 0);
    save_str_to_buf(&p.event->args_buf, (void *) &prog_name, 1);
    save_u64_arr_to_buf(&p.event->args_buf, (const u64 *) val.helpers, 4, 2);
    save_to_submit_buf(&p.event->args_buf, &prog_id, sizeof(u32), 3);
    save_to_submit_buf(&p.event->args_buf, &is_load, sizeof(bool), 4);

    events_perf_submit(&p, 0);

    return 0;
}

SEC("kprobe/bpf_check")
int BPF_KPROBE(trace_bpf_check)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPF_PROG))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // this probe is triggered when a bpf program is loaded.
    // we save the aux pointer to be used in security_bpf_prog, to indicate this prog is being
    // loaded - security_bpf_prog is triggered not only on prog load.

    struct bpf_prog **prog;
    struct bpf_prog *prog_ptr;
    struct bpf_prog_aux *prog_aux;

    prog = (struct bpf_prog **) PT_REGS_PARM1(ctx);
    bpf_core_read(&prog_ptr, sizeof(void *), prog);
    prog_aux = BPF_CORE_READ(prog_ptr, aux);

    bpf_map_update_elem(&bpf_prog_load_map, &p.event->context.task.host_tid, &prog_aux, BPF_ANY);

    return 0;
}

// Save in the temporary map 'bpf_attach_tmp_map' whether bpf_probe_write_user and
// bpf_override_return are used in the bpf program. Get this information in the verifier phase of
// the bpf program load lifecycle, before a prog_id is set for the bpf program. Save this
// information in a temporary map which includes the host_tid as key instead of the prog_id.
//
// Later on, in security_bpf_prog, save this information in the stable map 'bpf_attach_map', which
// contains the prog_id in its key.

statfunc int handle_bpf_helper_func_id(u32 host_tid, int func_id)
{
    bpf_used_helpers_t val = {0};

    // we want to the existing value in the map a just update it with the current func_id
    bpf_used_helpers_t *existing_val = bpf_map_lookup_elem(&bpf_attach_tmp_map, &host_tid);
    if (existing_val != NULL) {
        __builtin_memcpy(&val.helpers, &existing_val->helpers, sizeof(bpf_used_helpers_t));
    }

    // calculate where to encode usage of this func_id in bpf_used_helpers_t.
    // this method is used in order to stay in bounds of the helpers array and pass verifier checks.
    // it is equivalent to:
    //  val.helpers[func_id / 64] |= (1ULL << (func_id % 64));
    // which the verifier doesn't like.
    int arr_num;
    int arr_idx = func_id;

#pragma unroll
    for (int i = 0; i < NUM_OF_HELPERS_ELEMS; i++) {
        arr_num = i;
        if (arr_idx - SIZE_OF_HELPER_ELEM >= 0) {
            arr_idx = arr_idx - SIZE_OF_HELPER_ELEM;
        } else {
            break;
        }
    }
    if (arr_idx >= SIZE_OF_HELPER_ELEM) {
        // unsupported func_id
        return 0;
    }

    val.helpers[arr_num] |= (1ULL << (arr_idx));

    // update the map with the current func_id
    bpf_map_update_elem(&bpf_attach_tmp_map, &host_tid, &val, BPF_ANY);

    return 0;
}

SEC("kprobe/check_map_func_compatibility")
int BPF_KPROBE(trace_check_map_func_compatibility)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPF_PROG))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    int func_id = (int) PT_REGS_PARM3(ctx);

    return handle_bpf_helper_func_id(p.event->context.task.host_tid, func_id);
}

SEC("kprobe/check_helper_call")
int BPF_KPROBE(trace_check_helper_call)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_BPF_PROG))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    int func_id;

    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_for_each_map_elem)) {
        // if BPF_FUNC_for_each_map_elem doesn't exist under bpf_func_id - kernel version < 5.13
        func_id = (int) PT_REGS_PARM2(ctx);
    } else {
        struct bpf_insn *insn = (struct bpf_insn *) PT_REGS_PARM2(ctx);
        func_id = BPF_CORE_READ(insn, imm);
    }

    return handle_bpf_helper_func_id(p.event->context.task.host_tid, func_id);
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_KERNEL_READ_FILE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM2(ctx);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    save_str_to_buf(&p.event->args_buf, file_path, 0);
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 2);
    save_to_submit_buf(&p.event->args_buf, &type_id, sizeof(int), 3);
    save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_kernel_post_read_file")
int BPF_KPROBE(trace_security_kernel_post_read_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_POST_READ_FILE))
        return 0;

    if (!evaluate_scope_filters(&p) && !(p.config->options & OPT_CAPTURE_MODULES))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    char *buf = (char *) PT_REGS_PARM2(ctx);
    loff_t size = (loff_t) PT_REGS_PARM3(ctx);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM4(ctx);

    // Send event if chosen
    if (policies_matched(p.event)) {
        void *file_path = get_path_str(&file->f_path);
        save_str_to_buf(&p.event->args_buf, file_path, 0);
        save_to_submit_buf(&p.event->args_buf, &size, sizeof(loff_t), 1);
        save_to_submit_buf(&p.event->args_buf, &type_id, sizeof(int), 2);
        events_perf_submit(&p, 0);
    }

    if (p.config->options & OPT_CAPTURE_MODULES) {
        // Do not extract files greater than 4GB
        if (size >= (u64) 1 << 32) {
            return 0;
        }
        // Extract device id, inode number for file name
        dev_t s_dev = get_dev_from_file(file);
        unsigned long inode_nr = get_inode_nr_from_file(file);
        bin_args_t bin_args = {};
        u32 pid = p.event->context.task.host_pid;

        bin_args.type = SEND_KERNEL_MODULE;
        bpf_probe_read_kernel(bin_args.metadata, 4, &s_dev);
        bpf_probe_read_kernel(&bin_args.metadata[4], 8, &inode_nr);
        bpf_probe_read_kernel(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read_kernel(&bin_args.metadata[16], 4, &size);
        bin_args.start_off = 0;
        bin_args.ptr = buf;
        bin_args.full_size = size;

        tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
    }

    return 0;
}

SEC("kprobe/security_inode_mknod")
int BPF_KPROBE(trace_security_inode_mknod)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_INODE_MKNOD))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    unsigned short mode = (unsigned short) PT_REGS_PARM3(ctx);
    unsigned int dev = (unsigned int) PT_REGS_PARM4(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&p.event->args_buf, dentry_path, 0);
    save_to_submit_buf(&p.event->args_buf, &mode, sizeof(unsigned short), 1);
    save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/device_add")
int BPF_KPROBE(trace_device_add)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, DEVICE_ADD))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct device *dev = (struct device *) PT_REGS_PARM1(ctx);
    const char *name = get_device_name(dev);

    struct device *parent_dev = BPF_CORE_READ(dev, parent);
    const char *parent_name = get_device_name(parent_dev);

    save_str_to_buf(&p.event->args_buf, (void *) name, 0);
    save_str_to_buf(&p.event->args_buf, (void *) parent_name, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/__register_chrdev")
TRACE_ENT_FUNC(__register_chrdev, REGISTER_CHRDEV);

SEC("kretprobe/__register_chrdev")
int BPF_KPROBE(trace_ret__register_chrdev)
{
    args_t saved_args;
    if (load_args(&saved_args, REGISTER_CHRDEV) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(REGISTER_CHRDEV);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, REGISTER_CHRDEV))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    unsigned int major_number = (unsigned int) saved_args.args[0];
    unsigned int returned_major = PT_REGS_RC(ctx);

    // sets the returned major to the requested one in case of a successful registration
    if (major_number > 0 && returned_major == 0) {
        returned_major = major_number;
    }

    char *char_device_name = (char *) saved_args.args[3];
    struct file_operations *char_device_fops = (struct file_operations *) saved_args.args[4];

    save_to_submit_buf(&p.event->args_buf, &major_number, sizeof(unsigned int), 0);
    save_to_submit_buf(&p.event->args_buf, &returned_major, sizeof(unsigned int), 1);
    save_str_to_buf(&p.event->args_buf, char_device_name, 2);
    save_to_submit_buf(&p.event->args_buf, &char_device_fops, sizeof(void *), 3);

    return events_perf_submit(&p, 0);
}

statfunc struct pipe_buffer *get_last_write_pipe_buffer(struct pipe_inode_info *pipe)
{
    // Extract the last page buffer used in the pipe for write
    struct pipe_buffer *bufs = BPF_CORE_READ(pipe, bufs);
    unsigned int curbuf;

    struct pipe_inode_info___v54 *legacy_pipe = (struct pipe_inode_info___v54 *) pipe;
    if (bpf_core_field_exists(legacy_pipe->nrbufs)) {
        unsigned int nrbufs = BPF_CORE_READ(legacy_pipe, nrbufs);
        if (nrbufs > 0) {
            nrbufs--;
        }
        curbuf = (BPF_CORE_READ(legacy_pipe, curbuf) + nrbufs) &
                 (BPF_CORE_READ(legacy_pipe, buffers) - 1);
    } else {
        int head = BPF_CORE_READ(pipe, head);
        int ring_size = BPF_CORE_READ(pipe, ring_size);
        curbuf = (head - 1) & (ring_size - 1);
    }

    struct pipe_buffer *current_buffer = get_node_addr(bufs, curbuf);
    return current_buffer;
}

SEC("kprobe/do_splice")
TRACE_ENT_FUNC(do_splice, DIRTY_PIPE_SPLICE);

SEC("kretprobe/do_splice")
int BPF_KPROBE(trace_ret_do_splice)
{
    // The Dirty Pipe vulnerability exist in the kernel since version 5.8, so
    // there is not use to do logic if version is too old. In non-CORE, it will
    // even mean using defines which are not available in the kernel headers,
    // which will cause bugs.

    // Check if field of struct exist to determine kernel version - some fields
    // change between versions. In version 5.8 of the kernel, the field
    // "high_zoneidx" changed its name to "highest_zoneidx". This means that the
    // existence of the field "high_zoneidx" can indicate that the kernel
    // version is lower than v5.8

    struct alloc_context *check_508;
    if (bpf_core_field_exists(check_508->high_zoneidx)) {
        del_args(DIRTY_PIPE_SPLICE);
        return 0;
    }

    args_t saved_args;
    if (load_args(&saved_args, DIRTY_PIPE_SPLICE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(DIRTY_PIPE_SPLICE);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, DIRTY_PIPE_SPLICE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // Catch only successful splice
    if ((int) PT_REGS_RC(ctx) <= 0) {
        return 0;
    }

    struct file *out_file = (struct file *) saved_args.args[2];
    struct pipe_inode_info *out_pipe = get_file_pipe_info(out_file);
    // Check that output is a pipe
    if (!out_pipe) {
        return 0;
    }

    // dirty_pipe_splice is a splice to a pipe which results that the last page copied could be
    // modified (the PIPE_BUF_CAN_MERGE flag is on in the pipe_buffer struct).
    struct pipe_buffer *last_write_page_buffer = get_last_write_pipe_buffer(out_pipe);
    unsigned int out_pipe_last_buffer_flags = BPF_CORE_READ(last_write_page_buffer, flags);
    if ((out_pipe_last_buffer_flags & PIPE_BUF_FLAG_CAN_MERGE) == 0) {
        return 0;
    }

    struct file *in_file = (struct file *) saved_args.args[0];
    struct inode *in_inode = BPF_CORE_READ(in_file, f_inode);
    u64 in_inode_number = BPF_CORE_READ(in_inode, i_ino);
    unsigned short in_file_type = BPF_CORE_READ(in_inode, i_mode) & S_IFMT;
    void *in_file_path = get_path_str(__builtin_preserve_access_index(&in_file->f_path));
    size_t write_len = (size_t) saved_args.args[4];

    loff_t *off_in_addr = (loff_t *) saved_args.args[1];
    // In kernel v5.10 the pointer passed was no longer of the user, so flexibility is needed to
    // read it
    loff_t off_in;

    //
    // Check if field of struct exist to determine kernel version - some fields change between
    // versions. Field 'data' of struct 'public_key_signature' was introduced between v5.9 and
    // v5.10, so its existence might be used to determine whether the current version is older than
    // 5.9 or newer than 5.10.
    //
    // https://lore.kernel.org/stable/20210821203108.215937-1-rafaeldtinoco@gmail.com/
    //
    struct public_key_signature *check;

    if (!bpf_core_field_exists(check->data)) // version < v5.10
        bpf_core_read_user(&off_in, sizeof(off_in), off_in_addr);

    else // version >= v5.10
        bpf_core_read(&off_in, sizeof(off_in), off_in_addr);

    struct inode *out_inode = BPF_CORE_READ(out_file, f_inode);
    u64 out_inode_number = BPF_CORE_READ(out_inode, i_ino);

    // Only last page written to pipe is vulnerable from the end of written data
    loff_t next_exposed_data_offset_in_out_pipe_last_page =
        BPF_CORE_READ(last_write_page_buffer, offset) + BPF_CORE_READ(last_write_page_buffer, len);
    size_t in_file_size = BPF_CORE_READ(in_inode, i_size);
    size_t exposed_data_len = (PAGE_SIZE - 1) - next_exposed_data_offset_in_out_pipe_last_page;
    loff_t current_file_offset = off_in + write_len;
    if (current_file_offset + exposed_data_len > in_file_size) {
        exposed_data_len = in_file_size - current_file_offset - 1;
    }

    save_to_submit_buf(&p.event->args_buf, &in_inode_number, sizeof(u64), 0);
    save_to_submit_buf(&p.event->args_buf, &in_file_type, sizeof(unsigned short), 1);
    save_str_to_buf(&p.event->args_buf, in_file_path, 2);
    save_to_submit_buf(&p.event->args_buf, &current_file_offset, sizeof(loff_t), 3);
    save_to_submit_buf(&p.event->args_buf, &exposed_data_len, sizeof(size_t), 4);
    save_to_submit_buf(&p.event->args_buf, &out_inode_number, sizeof(u64), 5);
    save_to_submit_buf(&p.event->args_buf, &out_pipe_last_buffer_flags, sizeof(unsigned int), 6);

    return events_perf_submit(&p, 0);
}

SEC("raw_tracepoint/module_load")
int tracepoint__module__module_load(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, MODULE_LOAD))
        return 0;

    struct module *mod = (struct module *) ctx->args[0];

    if (event_is_selected(HIDDEN_KERNEL_MODULE_SEEKER, p.event->context.policies_version)) {
        u64 insert_time = get_current_time_in_ns();
        kernel_new_mod_t new_mod = {.insert_time = insert_time};
        u64 mod_addr = (u64) mod;
        // new_module_map - must be after the module is added to modules list,
        // otherwise there's a risk for race condition
        bpf_map_update_elem(&new_module_map, &mod_addr, &new_mod, BPF_ANY);

        last_module_insert_time = insert_time;
    }

    if (!evaluate_scope_filters(&p))
        return 0;

    if (p.event->context.syscall == SYSCALL_FINIT_MODULE) {
        struct pt_regs *task_regs = get_current_task_pt_regs();
        int fd = get_syscall_arg1(p.event->task, task_regs, false);
        struct file *file = get_struct_file_from_fd(fd);
        void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
        dev_t dev = get_dev_from_file(file);
        unsigned long inode = get_inode_nr_from_file(file);
        u64 ctime = get_ctime_nanosec_from_file(file);

        // add file related info
        save_str_to_buf(&p.event->args_buf, file_path, 3);
        save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 4);
        save_to_submit_buf(&p.event->args_buf, &inode, sizeof(unsigned long), 5);
        save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 6);
    }

    const char *version = BPF_CORE_READ(mod, version);
    const char *srcversion = BPF_CORE_READ(mod, srcversion);
    save_str_to_buf(&p.event->args_buf, &mod->name, 0);
    save_str_to_buf(&p.event->args_buf, (void *) version, 1);
    save_str_to_buf(&p.event->args_buf, (void *) srcversion, 2);

    return events_perf_submit(&p, 0);
}

SEC("raw_tracepoint/module_free")
int tracepoint__module__module_free(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, MODULE_FREE))
        return 0;

    struct module *mod = (struct module *) ctx->args[0];

    if (event_is_selected(HIDDEN_KERNEL_MODULE_SEEKER, p.event->context.policies_version)) {
        u64 mod_addr = (u64) mod;
        // We must delete before the actual deletion from modules list occurs, otherwise there's a
        // risk of race condition
        bpf_map_delete_elem(&new_module_map, &mod_addr);

        kernel_deleted_mod_t deleted_mod = {.deleted_time = get_current_time_in_ns()};
        bpf_map_update_elem(&recent_deleted_module_map, &mod_addr, &deleted_mod, BPF_ANY);
    }

    if (!evaluate_scope_filters(&p))
        return 0;

    const char *version = BPF_CORE_READ(mod, version);
    const char *srcversion = BPF_CORE_READ(mod, srcversion);
    save_str_to_buf(&p.event->args_buf, &mod->name, 0);
    save_str_to_buf(&p.event->args_buf, (void *) version, 1);
    save_str_to_buf(&p.event->args_buf, (void *) srcversion, 2);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/do_init_module")
TRACE_ENT_FUNC(do_init_module, DO_INIT_MODULE);

SEC("kretprobe/do_init_module")
int BPF_KPROBE(trace_ret_do_init_module)
{
    args_t saved_args;
    if (load_args(&saved_args, DO_INIT_MODULE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(DO_INIT_MODULE);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, HIDDEN_KERNEL_MODULE_SEEKER))
        return 0;

    struct module *mod = (struct module *) saved_args.args[0];

    // trigger the lkm seeker
    if (evaluate_scope_filters(&p)) {
        u64 addr = (u64) mod;
        u32 flags = FULL_SCAN;
        lkm_seeker_send_to_userspace((struct module *) addr, &flags, &p);
    }

    // save strings to buf
    const char *version = BPF_CORE_READ(mod, version);
    const char *srcversion = BPF_CORE_READ(mod, srcversion);

    if (!reset_event(p.event, DO_INIT_MODULE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    save_str_to_buf(&p.event->args_buf, &mod->name, 0);
    save_str_to_buf(&p.event->args_buf, (void *) version, 1);
    save_str_to_buf(&p.event->args_buf, (void *) srcversion, 2);

    int ret_val = PT_REGS_RC(ctx);
    return events_perf_submit(&p, ret_val);
}

// clang-format off

SEC("kprobe/load_elf_phdrs")
int BPF_KPROBE(trace_load_elf_phdrs)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, LOAD_ELF_PHDRS))
        return 0;

    proc_info_t *proc_info = p.proc_info;

    struct file *loaded_elf = (struct file *) PT_REGS_PARM2(ctx);
    const char *elf_pathname = (char *) get_path_str(__builtin_preserve_access_index(&loaded_elf->f_path));

    // The interpreter field will be updated for any loading of an elf, both for the binary and for
    // the interpreter. Because the interpreter is loaded only after the executed elf is loaded, the
    // value of the executed binary should be overridden by the interpreter.

    size_t sz = sizeof(proc_info->interpreter.pathname);
    bpf_probe_read_kernel_str(proc_info->interpreter.pathname, sz, elf_pathname);
    proc_info->interpreter.id.device = get_dev_from_file(loaded_elf);
    proc_info->interpreter.id.inode = get_inode_nr_from_file(loaded_elf);
    proc_info->interpreter.id.ctime = get_ctime_nanosec_from_file(loaded_elf);

    if (!evaluate_scope_filters(&p))
        return 0;

    save_str_to_buf(&p.event->args_buf, (void *) elf_pathname, 0);
    save_to_submit_buf(&p.event->args_buf, &proc_info->interpreter.id.device, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &proc_info->interpreter.id.inode, sizeof(unsigned long), 2);
    events_perf_submit(&p, 0);

    return 0;
}

// clang-format on

SEC("kprobe/security_file_permission")
int BPF_KPROBE(trace_security_file_permission)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == NULL)
        return 0;
    struct inode *f_inode = get_inode_from_file(file);
    struct super_block *i_sb = get_super_block_from_inode(f_inode);
    unsigned long s_magic = get_s_magic_from_super_block(i_sb);

    // Only check procfs entries
    if (s_magic != PROC_SUPER_MAGIC) {
        return 0;
    }

    program_data_t p = {};
    if (!init_program_data(&p, ctx, HOOKED_PROC_FOPS))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct file_operations *fops = (struct file_operations *) BPF_CORE_READ(f_inode, i_fop);
    if (fops == NULL)
        return 0;

    unsigned long iterate_addr = 0;
    unsigned long iterate_shared_addr = (unsigned long) BPF_CORE_READ(fops, iterate_shared);

    // iterate() removed by commit 3e3271549670 at v6.5-rc4
    if (bpf_core_field_exists(fops->iterate))
        iterate_addr = (unsigned long) BPF_CORE_READ(fops, iterate);

    if (iterate_addr == 0 && iterate_shared_addr == 0)
        return 0;

    // get text segment bounds
    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    // mark as 0 if in bounds
    if (iterate_shared_addr >= (u64) stext_addr && iterate_shared_addr < (u64) etext_addr)
        iterate_shared_addr = 0;
    if (iterate_addr >= (u64) stext_addr && iterate_addr < (u64) etext_addr)
        iterate_addr = 0;

    // now check again, if both are in text bounds, return
    if (iterate_addr == 0 && iterate_shared_addr == 0)
        return 0;

    unsigned long fops_addresses[2] = {iterate_shared_addr, iterate_addr};

    save_u64_arr_to_buf(&p.event->args_buf, (const u64 *) fops_addresses, 2, 0);
    events_perf_submit(&p, 0);
    return 0;
}

SEC("raw_tracepoint/task_rename")
int tracepoint__task__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, TASK_RENAME))
        return 0;

    if (!evaluate_scope_filters((&p)))
        return 0;

    struct task_struct *tsk = (struct task_struct *) ctx->args[0];
    char old_name[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(&old_name, TASK_COMM_LEN, tsk->comm);
    const char *new_name = (const char *) ctx->args[1];

    save_str_to_buf(&p.event->args_buf, (void *) old_name, 0);
    save_str_to_buf(&p.event->args_buf, (void *) new_name, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(trace_security_inode_rename)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_INODE_RENAME))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct dentry *old_dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *) PT_REGS_PARM4(ctx);

    void *old_dentry_path = get_dentry_path_str(old_dentry);
    save_str_to_buf(&p.event->args_buf, old_dentry_path, 0);
    void *new_dentry_path = get_dentry_path_str(new_dentry);
    save_str_to_buf(&p.event->args_buf, new_dentry_path, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/kallsyms_lookup_name")
TRACE_ENT_FUNC(kallsyms_lookup_name, KALLSYMS_LOOKUP_NAME);

SEC("kretprobe/kallsyms_lookup_name")
int BPF_KPROBE(trace_ret_kallsyms_lookup_name)
{
    args_t saved_args;
    if (load_args(&saved_args, KALLSYMS_LOOKUP_NAME) != 0)
        return 0;
    del_args(KALLSYMS_LOOKUP_NAME);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, KALLSYMS_LOOKUP_NAME))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    char *name = (char *) saved_args.args[0];
    unsigned long address = PT_REGS_RC(ctx);

    save_str_to_buf(&p.event->args_buf, name, 0);
    save_to_submit_buf(&p.event->args_buf, &address, sizeof(unsigned long), 1);

    return events_perf_submit(&p, 0);
}

enum signal_handling_method_e
{
    SIG_DFL,
    SIG_IGN,
    SIG_HND = 2 // Doesn't exist in the kernel, but signifies that the method is through
                // user-defined handler
};

SEC("kprobe/do_sigaction")
int BPF_KPROBE(trace_do_sigaction)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, DO_SIGACTION))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // Initialize all relevant arguments values
    int sig = (int) PT_REGS_PARM1(ctx);
    u8 old_handle_method = 0, new_handle_method = 0;
    unsigned long new_sa_flags, old_sa_flags;
    void *new_sa_handler, *old_sa_handler;
    unsigned long new_sa_mask, old_sa_mask;

    // Extract old signal handler values
    struct task_struct *task = p.event->task;
    struct sighand_struct *sighand = BPF_CORE_READ(task, sighand);
    struct k_sigaction *sig_actions = &(sighand->action[0]);
    if (sig > 0 && sig < _NSIG) {
        struct k_sigaction *old_act = get_node_addr(sig_actions, sig - 1);
        old_sa_flags = BPF_CORE_READ(old_act, sa.sa_flags);
        // In 64-bit system there is only 1 node in the mask array
        old_sa_mask = BPF_CORE_READ(old_act, sa.sa_mask.sig[0]);
        old_sa_handler = BPF_CORE_READ(old_act, sa.sa_handler);
        if (old_sa_handler >= (void *) SIG_HND)
            old_handle_method = SIG_HND;
        else {
            old_handle_method = (u8) (old_sa_handler && 0xFF);
            old_sa_handler = NULL;
        }
    }

    // Check if a pointer for storing old signal handler is given
    struct k_sigaction *recv_old_act = (struct k_sigaction *) PT_REGS_PARM3(ctx);
    bool old_act_initialized = recv_old_act != NULL;

    // Extract new signal handler values if initialized
    struct k_sigaction *new_act = (struct k_sigaction *) PT_REGS_PARM2(ctx);
    bool new_act_initialized = new_act != NULL;
    if (new_act_initialized) {
        struct sigaction *new_sigaction = &new_act->sa;
        new_sa_flags = BPF_CORE_READ(new_sigaction, sa_flags);
        // In 64-bit system there is only 1 node in the mask array
        new_sa_mask = BPF_CORE_READ(new_sigaction, sa_mask.sig[0]);
        new_sa_handler = BPF_CORE_READ(new_sigaction, sa_handler);
        if (new_sa_handler >= (void *) SIG_HND)
            new_handle_method = SIG_HND;
        else {
            new_handle_method = (u8) (new_sa_handler && 0xFF);
            new_sa_handler = NULL;
        }
    }

    save_to_submit_buf(&p.event->args_buf, &sig, sizeof(int), 0);
    save_to_submit_buf(&p.event->args_buf, &new_act_initialized, sizeof(bool), 1);
    if (new_act_initialized) {
        save_to_submit_buf(&p.event->args_buf, &new_sa_flags, sizeof(unsigned long), 2);
        save_to_submit_buf(&p.event->args_buf, &new_sa_mask, sizeof(unsigned long), 3);
        save_to_submit_buf(&p.event->args_buf, &new_handle_method, sizeof(u8), 4);
        save_to_submit_buf(&p.event->args_buf, &new_sa_handler, sizeof(void *), 5);
    }
    save_to_submit_buf(&p.event->args_buf, &old_act_initialized, sizeof(bool), 6);
    save_to_submit_buf(&p.event->args_buf, &old_sa_flags, sizeof(unsigned long), 7);
    save_to_submit_buf(&p.event->args_buf, &old_sa_mask, sizeof(unsigned long), 8);
    save_to_submit_buf(&p.event->args_buf, &old_handle_method, sizeof(u8), 9);
    save_to_submit_buf(&p.event->args_buf, &old_sa_handler, sizeof(void *), 10);

    return events_perf_submit(&p, 0);
}

statfunc int common_utimes(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, VFS_UTIMES))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct path *path = (struct path *) PT_REGS_PARM1(ctx);
    struct timespec64 *times = (struct timespec64 *) PT_REGS_PARM2(ctx);

    void *path_str = get_path_str(path);

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    u64 inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    u64 atime = get_time_nanosec_timespec(times);
    u64 mtime = get_time_nanosec_timespec(&times[1]);

    save_str_to_buf(&p.event->args_buf, path_str, 0);
    save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(u64), 2);
    save_to_submit_buf(&p.event->args_buf, &atime, sizeof(u64), 3);
    save_to_submit_buf(&p.event->args_buf, &mtime, sizeof(u64), 4);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/vfs_utimes")
int BPF_KPROBE(trace_vfs_utimes)
{
    return common_utimes(ctx);
}

SEC("kprobe/utimes_common")
int BPF_KPROBE(trace_utimes_common)
{
    return common_utimes(ctx);
}

SEC("kprobe/do_truncate")
int BPF_KPROBE(trace_do_truncate)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, DO_TRUNCATE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    u64 length = (long) PT_REGS_PARM3(ctx);

    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    save_str_to_buf(&p.event->args_buf, dentry_path, 0);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 2);
    save_to_submit_buf(&p.event->args_buf, &length, sizeof(u64), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, FILE_MODIFICATION))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM2(ctx);

    // check if regular file. otherwise don't save the file_mod_key_t in file_modification_map.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.id.device, file_info.id.inode};
    int op = FILE_MODIFICATION_SUBMIT;

    bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);

    return 0;
}

SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, FILE_MODIFICATION))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.id.device, file_info.id.inode};

    bpf_map_delete_elem(&file_modification_map, &file_mod_key);

    return 0;
}

statfunc int common_file_modification_ent(struct pt_regs *ctx)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);

    // check if regular file. otherwise don't output the event.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    u64 ctime = get_ctime_nanosec_from_file(file);

    args_t args = {};
    args.args[0] = (unsigned long) file;
    args.args[1] = ctime;
    save_args(&args, FILE_MODIFICATION);

    return 0;
}

statfunc int common_file_modification_ret(struct pt_regs *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;
    del_args(FILE_MODIFICATION);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, FILE_MODIFICATION))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct file *file = (struct file *) saved_args.args[0];
    u64 old_ctime = saved_args.args[1];

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.id.device, file_info.id.inode};

    int *op = bpf_map_lookup_elem(&file_modification_map, &file_mod_key);
    if (op == NULL || *op == FILE_MODIFICATION_SUBMIT) {
        // we should submit the event once and mark as done.
        int op = FILE_MODIFICATION_DONE;
        bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);
    } else {
        // no need to submit. return.
        return 0;
    }

    save_str_to_buf(&p.event->args_buf, file_info.pathname_p, 0);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.device, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.inode, sizeof(unsigned long), 2);
    save_to_submit_buf(&p.event->args_buf, &old_ctime, sizeof(u64), 3);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.ctime, sizeof(u64), 4);

    events_perf_submit(&p, 0);

    return 0;
}

SEC("kprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time)
{
    return common_file_modification_ent(ctx);
}

SEC("kretprobe/file_update_time")
int BPF_KPROBE(trace_ret_file_update_time)
{
    return common_file_modification_ret(ctx);
}

SEC("kprobe/file_modified")
int BPF_KPROBE(trace_file_modified)
{
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ent(ctx);
    }

    return 0;
}

SEC("kretprobe/file_modified")
int BPF_KPROBE(trace_ret_file_modified)
{
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ret(ctx);
    }

    return 0;
}

SEC("kprobe/inotify_find_inode")
TRACE_ENT_FUNC(inotify_find_inode, INOTIFY_WATCH);

SEC("kretprobe/inotify_find_inode")
int BPF_KPROBE(trace_ret_inotify_find_inode)
{
    args_t saved_args;
    if (load_args(&saved_args, INOTIFY_WATCH) != 0)
        return 0;
    del_args(INOTIFY_WATCH);

    program_data_t p = {};
    if (!init_program_data(&p, ctx, INOTIFY_WATCH))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct path *path = (struct path *) saved_args.args[1];

    void *path_str = get_path_str(path);

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    u64 inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    save_str_to_buf(&p.event->args_buf, path_str, 0);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&p, 0);
}

statfunc int submit_process_execute_failed(struct pt_regs *ctx, program_data_t *p)
{
    if (!evaluate_scope_filters(p))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    if (bprm == NULL) {
        return -1;
    }

    struct file *file = get_file_ptr_from_bprm(bprm);

    const char *path = get_binprm_filename(bprm);
    save_str_to_buf(&p->event->args_buf, (void *) path, 2);

    void *binary_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
    save_str_to_buf(&p->event->args_buf, binary_path, 3);

    dev_t binary_device_id = get_dev_from_file(file);
    save_to_submit_buf(&p->event->args_buf, &binary_device_id, sizeof(dev_t), 4);

    unsigned long binary_inode_number = get_inode_nr_from_file(file);
    save_to_submit_buf(&p->event->args_buf, &binary_inode_number, sizeof(unsigned long), 5);

    u64 binary_ctime = get_ctime_nanosec_from_file(file);
    save_to_submit_buf(&p->event->args_buf, &binary_ctime, sizeof(u64), 6);

    umode_t binary_inode_mode = get_inode_mode_from_file(file);
    save_to_submit_buf(&p->event->args_buf, &binary_inode_mode, sizeof(umode_t), 7);

    const char *interpreter_path = get_binprm_interp(bprm);
    save_str_to_buf(&p->event->args_buf, (void *) interpreter_path, 8);

    bpf_tail_call(ctx, &prog_array, TAIL_PROCESS_EXECUTE_FAILED);
    return -1;
}

SEC("kprobe/process_execute_failed_tail")
int process_execute_failed_tail(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    struct file *stdin_file = get_struct_file_from_fd(0);

    unsigned short stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
    save_to_submit_buf(&p.event->args_buf, &stdin_type, sizeof(unsigned short), 9);

    void *stdin_path = get_path_str(__builtin_preserve_access_index(&stdin_file->f_path));
    save_str_to_buf(&p.event->args_buf, stdin_path, 10);

    int kernel_invoked = (get_task_parent_flags(task) & PF_KTHREAD) ? 1 : 0;
    save_to_submit_buf(&p.event->args_buf, &kernel_invoked, sizeof(int), 11);

    return events_perf_submit(&p, 0);
}

bool use_security_bprm_creds_for_exec = false;

SEC("kprobe/exec_binprm")
int BPF_KPROBE(trace_exec_binprm)
{
    if (use_security_bprm_creds_for_exec) {
        return 0;
    }

    program_data_t p = {};
    if (!init_program_data(&p, ctx, PROCESS_EXECUTE_FAILED_INTERNAL))
        return 0;
    return submit_process_execute_failed(ctx, &p);
}

SEC("kprobe/security_bprm_creds_for_exec")
int BPF_KPROBE(trace_security_bprm_creds_for_exec)
{
    use_security_bprm_creds_for_exec = true;
    program_data_t p = {};
    if (!init_program_data(&p, ctx, PROCESS_EXECUTE_FAILED_INTERNAL))
        return 0;
    return submit_process_execute_failed(ctx, &p);
}

SEC("kretprobe/execute_finished")
int BPF_KPROBE(trace_execute_finished)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, EXECUTE_FINISHED))
        return -1;

    if (!evaluate_scope_filters(&p))
        return 0;

    // We can enrich the event with user provided arguments. If we have kernelspace arguments,
    // the userspace arguments will be discarded.
    struct pt_regs *task_regs = get_current_task_pt_regs();
    u64 argv, envp;
    void *path;

    if (p.event->context.syscall == SYSCALL_EXECVEAT) {
        int dirfd = get_syscall_arg1(p.event->task, task_regs, false);
        path = (void *) get_syscall_arg2(p.event->task, task_regs, false);
        argv = get_syscall_arg3(p.event->task, task_regs, false);
        envp = get_syscall_arg4(p.event->task, task_regs, false);
        int flags = get_syscall_arg5(p.event->task, task_regs, false);

        // send args unique to execevat
        save_to_submit_buf(&p.event->args_buf, &dirfd, sizeof(int), 0);
        save_to_submit_buf(&p.event->args_buf, &flags, sizeof(int), 1);
    } else {
        path = (void *) get_syscall_arg1(p.event->task, task_regs, false);
        argv = get_syscall_arg2(p.event->task, task_regs, false);
        envp = get_syscall_arg3(p.event->task, task_regs, false);
    }

    save_str_to_buf(&p.event->args_buf, path, 2);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) argv, 12);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(&p.event->args_buf, (const char *const *) envp, 13);
    }

    long exec_ret = PT_REGS_RC(ctx);
    return events_perf_submit(&p, exec_ret);
}

SEC("kprobe/security_path_notify")
int BPF_KPROBE(trace_security_path_notify)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_PATH_NOTIFY))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct path *path = (struct path *) PT_REGS_PARM1(ctx);
    void *path_str = get_path_str(path);
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    u64 inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    u64 mask = PT_REGS_PARM2(ctx);
    unsigned int obj_type = PT_REGS_PARM3(ctx);

    save_str_to_buf(&p.event->args_buf, path_str, 0);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 2);
    save_to_submit_buf(&p.event->args_buf, &mask, sizeof(u64), 3);
    save_to_submit_buf(&p.event->args_buf, &obj_type, sizeof(unsigned int), 4);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/set_fs_pwd")
int BPF_KPROBE(trace_set_fs_pwd)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SET_FS_PWD))
        return 0;

    if (p.event->context.syscall != SYSCALL_CHDIR && p.event->context.syscall != SYSCALL_FCHDIR)
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    if (get_task_parent_flags(p.event->task) & PF_KTHREAD)
        return 0;

    void *unresolved_path = NULL;
    if (p.event->context.syscall == SYSCALL_CHDIR) {
        struct pt_regs *task_regs = get_current_task_pt_regs();
        unresolved_path = (void *) get_syscall_arg1(p.event->task, task_regs, false);
    }

    void *resolved_path = get_path_str((struct path *) PT_REGS_PARM2(ctx));

    save_str_to_buf(&p.event->args_buf, unresolved_path, 0);
    save_str_to_buf(&p.event->args_buf, resolved_path, 1);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_task_setrlimit")
int BPF_KPROBE(trace_security_task_setrlimit)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_TASK_SETRLIMIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct task_struct *task = (struct task_struct *) PT_REGS_PARM1(ctx);
    unsigned int resource = (unsigned int) PT_REGS_PARM2(ctx);
    struct rlimit *new_rlim = (struct rlimit *) PT_REGS_PARM3(ctx);

    u32 target_host_tgid = get_task_host_tgid(task);
    u64 new_rlim_cur = BPF_CORE_READ(new_rlim, rlim_cur);
    u64 new_rlim_max = BPF_CORE_READ(new_rlim, rlim_max);

    save_to_submit_buf(&p.event->args_buf, &target_host_tgid, sizeof(u32), 0);
    save_to_submit_buf(&p.event->args_buf, &resource, sizeof(unsigned int), 1);
    save_to_submit_buf(&p.event->args_buf, &new_rlim_cur, sizeof(u64), 2);
    save_to_submit_buf(&p.event->args_buf, &new_rlim_max, sizeof(u64), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/security_settime64")
int BPF_KPROBE(trace_security_settime64)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_SETTIME64))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    const struct timespec64 *ts = (const struct timespec64 *) PT_REGS_PARM1(ctx);
    const struct timezone *tz = (const struct timezone *) PT_REGS_PARM2(ctx);

    u64 tv_sec = BPF_CORE_READ(ts, tv_sec);
    u64 tv_nsec = BPF_CORE_READ(ts, tv_nsec);

    int tz_minuteswest = BPF_CORE_READ(tz, tz_minuteswest);
    int tz_dsttime = BPF_CORE_READ(tz, tz_dsttime);

    save_to_submit_buf(&p.event->args_buf, &tv_sec, sizeof(u64), 0);
    save_to_submit_buf(&p.event->args_buf, &tv_nsec, sizeof(u64), 1);
    save_to_submit_buf(&p.event->args_buf, &tz_minuteswest, sizeof(int), 2);
    save_to_submit_buf(&p.event->args_buf, &tz_dsttime, sizeof(int), 3);

    return events_perf_submit(&p, 0);
}

SEC("kprobe/chmod_common")
int BPF_KPROBE(trace_chmod_common)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CHMOD_COMMON))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    struct path *path = (struct path *) PT_REGS_PARM1(ctx);
    umode_t mode = PT_REGS_PARM2(ctx);
    void *file_path = get_path_str(path);

    save_str_to_buf(&p.event->args_buf, file_path, 0);
    save_to_submit_buf(&p.event->args_buf, &mode, sizeof(umode_t), 1);

    return events_perf_submit(&p, 0);
}

//
// Syscall checkers
//

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} suspicious_syscall_source_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} stack_pivot_syscalls SEC(".maps");

statfunc void check_suspicious_syscall_source(void *ctx, struct pt_regs *regs, u32 syscall)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SUSPICIOUS_SYSCALL_SOURCE))
        return;

    if (!evaluate_scope_filters(&p))
        return;

    // Get instruction pointer
    u64 ip = PT_REGS_IP_CORE(regs);

    // Find VMA which contains the instruction pointer
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (unlikely(task == NULL))
        return;
    struct vm_area_struct *vma = find_vma(ctx, task, ip);
    if (unlikely(vma == NULL))
        return;

    // If the VMA is file-backed, the syscall is determined to be legitimate
    if (vma_is_file_backed(vma))
        return;

    // Build a key that identifies the combination of syscall,
    // source VMA and process so we don't submit it multiple times
    syscall_source_key_t key = {.syscall = syscall,
                                .tgid = get_task_host_tgid(task),
                                .tgid_start_time = get_task_start_time(get_leader_task(task)),
                                .vma_addr = BPF_CORE_READ(vma, vm_start)};
    bool val = true;

    // Try updating the map with the requirement that this key does not exist yet
    if ((int) bpf_map_update_elem(&syscall_source_map, &key, &val, BPF_NOEXIST) == -EEXIST)
        // This key already exists, no need to submit the same syscall-vma-process combination again
        return;

    const char *vma_type_str = get_vma_type_str(get_vma_type(p.task_info, vma));
    unsigned long vma_start = BPF_CORE_READ(vma, vm_start);
    unsigned long vma_size = BPF_CORE_READ(vma, vm_end) - vma_start;
    unsigned long vma_flags = BPF_CORE_READ(vma, vm_flags);

    save_to_submit_buf(&p.event->args_buf, &syscall, sizeof(syscall), 0);
    save_to_submit_buf(&p.event->args_buf, &ip, sizeof(ip), 1);
    save_str_to_buf(&p.event->args_buf, (void *) vma_type_str, 2);
    save_to_submit_buf(&p.event->args_buf, &vma_start, sizeof(vma_start), 3);
    save_to_submit_buf(&p.event->args_buf, &vma_size, sizeof(vma_size), 4);
    save_to_submit_buf(&p.event->args_buf, &vma_flags, sizeof(vma_flags), 5);

    events_perf_submit(&p, 0);
}

statfunc void check_stack_pivot(void *ctx, struct pt_regs *regs, u32 syscall)
{
    program_data_t p = {};

    if (!init_program_data(&p, ctx, STACK_PIVOT))
        return;

    if (!evaluate_scope_filters(&p))
        return;

    // Get stack pointer
    u64 sp = PT_REGS_SP_CORE(regs);

    // Find VMA which contains the stack pointer
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (unlikely(task == NULL))
        return;
    struct vm_area_struct *vma = find_vma(ctx, task, sp);
    if (unlikely(vma == NULL))
        return;

    // Check if the stack pointer points to the stack region.
    //
    // Goroutine stacks are allocated on golang's heap, which means that an
    // exploit performing a stack pivot on a go program will result in a false
    // negative if the new stack location is on golang's heap.
    //
    // To identify thread stacks, they need to be tracked when new threads are
    // created. This means that we cannot identify stacks of threads that were
    // created before tracee started. To avoid false positives, we ignore events
    // where the stack pointer's VMA might be a thread stack but it was not
    // tracked for this thread. This may result in false negatives.
    enum vma_type vma_type = get_vma_type(p.task_info, vma);
    if (vma_type == VMA_MAIN_STACK || vma_type == VMA_GOLANG_HEAP || vma_type == VMA_THREAD_STACK ||
        (vma_type == VMA_ANON && !thread_stack_tracked(p.task_info)))
        return;

    const char *vma_type_str = get_vma_type_str(vma_type);
    unsigned long vma_start = BPF_CORE_READ(vma, vm_start);
    unsigned long vma_size = BPF_CORE_READ(vma, vm_end) - vma_start;
    unsigned long vma_flags = BPF_CORE_READ(vma, vm_flags);

    save_to_submit_buf(&p.event->args_buf, &syscall, sizeof(syscall), 0);
    save_to_submit_buf(&p.event->args_buf, &sp, sizeof(sp), 1);
    save_str_to_buf(&p.event->args_buf, (void *) vma_type_str, 2);
    save_to_submit_buf(&p.event->args_buf, &vma_start, sizeof(vma_start), 3);
    save_to_submit_buf(&p.event->args_buf, &vma_size, sizeof(vma_size), 4);
    save_to_submit_buf(&p.event->args_buf, &vma_flags, sizeof(vma_flags), 5);

    events_perf_submit(&p, 0);
}

SEC("kprobe/syscall_checker")
int BPF_KPROBE(syscall_checker)
{
    // Get user registers
    struct pt_regs *regs = ctx;
    if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER))
        regs = (struct pt_regs *) PT_REGS_PARM1(ctx);

    // Get syscall ID
    u32 syscall = get_syscall_id_from_regs(regs);

    if (bpf_map_lookup_elem(&suspicious_syscall_source_syscalls, &syscall) != NULL)
        check_suspicious_syscall_source(ctx, regs, syscall);

    if (bpf_map_lookup_elem(&stack_pivot_syscalls, &syscall) != NULL)
        check_stack_pivot(ctx, regs, syscall);

    return 0;
}

// clang-format off

// Network Packets (works from ~5.2 and beyond)

// To track ingress/egress traffic we always need to link a flow to its related
// task (particularly when hooking ingress skb bpf programs, where the current
// task is typically a kernel thread).

// In older kernels, managing cgroup skb programs can be more difficult due to
// the lack of bpf helpers and buggy/incomplete verifier. To deal with this,
// this approach uses a technique of kprobing the function responsible for
// calling the cgroup/skb programs.

// Tracee utilizes a technique of kprobing the function responsible for calling
// the cgroup/skb programs in order to perform the tasks which cgroup skb
// programs would usually accomplish. Through this method, all the data needed
// by the cgroup/skb programs is already stored in a map.

// Unfortunately this approach has some cons: the kprobe to cgroup/skb execution
// flow does not have preemption disabled, so the map used in between all the
// hooks need to use as a key something that is available to all the hooks
// context (the packet contents themselves: e.g. L3 header fields).

// At the end, the logic is simple: every time a socket is created an inode is
// also created. The task owning the socket is indexed by the socket inode so
// everytime this socket is used we know which task it belongs to (specially
// during ingress hook, executed from the softirq context within a kthread).

//
// network helper functions
//

statfunc bool is_family_supported(struct socket *sock)
{
    struct sock *sk = (void *) BPF_CORE_READ(sock, sk);
    struct sock_common *common = (void *) sk;
    u8 family = BPF_CORE_READ(common, skc_family);

    switch (family) {
        case PF_INET:
        case PF_INET6:
            break;
        // case PF_UNSPEC:
        // case PF_LOCAL:      // PF_UNIX or PF_FILE
        // case PF_NETLINK:
        // case PF_VSOCK:
        // case PF_XDP:
        // case PF_BRIDGE:
        // case PF_PACKET:
        // case PF_MPLS:
        // case PF_BLUETOOTH:
        // case PF_IB:
        // ...
        default:
            return 0; // not supported
    }

    return 1; // supported
}

statfunc bool is_socket_supported(struct socket *sock)
{
    struct sock *sk = (void *) BPF_CORE_READ(sock, sk);
    u16 protocol = get_sock_protocol(sk);
    switch (protocol) {
        // case IPPROTO_IPIP:
        // case IPPROTO_DCCP:
        // case IPPROTO_SCTP:
        // case IPPROTO_UDPLITE:
        case IPPROTO_IP:
        case IPPROTO_IPV6:
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            break;
        default:
            return 0; // not supported
    }

    return 1; // supported
}

//
// Support functions for network code
//

statfunc u64 sizeof_net_event_context_t(void)
{
    return sizeof(net_event_context_t) - sizeof(net_event_contextmd_t);
}

statfunc void set_net_task_context(event_data_t *event, net_task_context_t *netctx)
{
    netctx->task = event->task;
    netctx->policies_version = event->context.policies_version;
    netctx->matched_policies = event->context.matched_policies;
    netctx->syscall = event->context.syscall;
    __builtin_memset(&netctx->taskctx, 0, sizeof(task_context_t));
    __builtin_memcpy(&netctx->taskctx, &event->context.task, sizeof(task_context_t));
}

statfunc enum event_id_e net_packet_to_net_event(net_packet_t packet_type)
{
    switch (packet_type) {
        case CAP_NET_PACKET:
            return NET_CAPTURE_BASE;
        // Packets
        case SUB_NET_PACKET_RAW:
            return NET_PACKET_RAW;
        case SUB_NET_PACKET_IP:
            return NET_PACKET_IP;
        case SUB_NET_PACKET_TCP:
            return NET_PACKET_TCP;
        case SUB_NET_PACKET_UDP:
            return NET_PACKET_UDP;
        case SUB_NET_PACKET_ICMP:
            return NET_PACKET_ICMP;
        case SUB_NET_PACKET_ICMPV6:
            return NET_PACKET_ICMPV6;
        case SUB_NET_PACKET_DNS:
            return NET_PACKET_DNS;
        case SUB_NET_PACKET_HTTP:
            return NET_PACKET_HTTP;
    };
    return MAX_EVENT_ID;
}

// The address of &neteventctx->eventctx will be aligned as eventctx is the
// first member of that packed struct. This is a false positive as we do need
// the neteventctx struct to be all packed.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"

// Return if a network event should to be sumitted: if any of the policies
// matched, submit the network event. This means that if any of the policies
// need a network event, kernel can submit the network base event and let
// userland deal with it (derived events will match the appropriate policies).
statfunc u64 should_submit_net_event(net_event_context_t *neteventctx,
                                     net_packet_t packet_type)
{
    enum event_id_e evt_id = net_packet_to_net_event(packet_type);

    u16 version = neteventctx->eventctx.policies_version;
    void *inner_events_map = bpf_map_lookup_elem(&events_map_version, &version);
    if (inner_events_map == NULL)
        return 0;

    event_config_t *evt_config = bpf_map_lookup_elem(inner_events_map, &evt_id);
    if (evt_config == NULL)
        return 0;

    return evt_config->submit_for_policies & neteventctx->eventctx.matched_policies;
}

#pragma clang diagnostic pop // -Waddress-of-packed-member

// Return if a network flow event should be submitted.
statfunc bool should_submit_flow_event(net_event_context_t *neteventctx)
{
    switch (neteventctx->md.should_flow) {
        case 0:
            break;
        case 1:
            return true;
        case 2:
            return false;
    }

    u32 evt_id = NET_FLOW_BASE;

    // Again, if any policy matched, submit the flow base event so other flow
    // events can be derived in userland and their policies matched in userland.
    event_config_t *evt_config = bpf_map_lookup_elem(&events_map, &evt_id);
    if (evt_config == NULL)
        return 0;

    u64 should = evt_config->submit_for_policies & neteventctx->eventctx.matched_policies;

    // Cache the result so next time we don't need to check again.
    if (should)
        neteventctx->md.should_flow = 1; // cache result: submit flow events
    else
        neteventctx->md.should_flow = 2; // cache result: don't submit flow events

    return should ? true : false;
}

// Return if a network capture event should be submitted.
statfunc u64 should_capture_net_event(net_event_context_t *neteventctx, net_packet_t packet_type)
{
    if (neteventctx->md.captured) // already captured
        return 0;

    return should_submit_net_event(neteventctx, packet_type);
}

//
// Protocol parsing functions
//

#define CGROUP_SKB_HANDLE_FUNCTION(name)                                       \
statfunc u32 cgroup_skb_handle_##name(                                         \
    struct __sk_buff *ctx,                                                     \
    net_event_context_t *neteventctx,                                          \
    nethdrs *nethdrs                                                           \
)

CGROUP_SKB_HANDLE_FUNCTION(family);
CGROUP_SKB_HANDLE_FUNCTION(proto);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_http);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_icmp);
CGROUP_SKB_HANDLE_FUNCTION(proto_icmpv6);

#define CGROUP_SKB_HANDLE(name) cgroup_skb_handle_##name(ctx, neteventctx, nethdrs);

//
// Network submission functions
//

// Submit a network event (packet, capture, flow) to userland.
statfunc u32 cgroup_skb_submit(void *map, struct __sk_buff *ctx,
                               net_event_context_t *neteventctx,
                               u32 event_type, u32 size)
{
    size = size > FULL ? FULL : size;
    switch (size) {
        case HEADERS: // submit only headers
            size = neteventctx->md.header_size;
            break;
        case FULL: // submit full packet
            size = ctx->len;
            break;
        default: // submit size bytes
            size += neteventctx->md.header_size;
            size = size > ctx->len ? ctx->len : size;
            break;
    }

    // Flag eBPF subsystem to use current CPU and copy size bytes of payload.
    u64 flags = BPF_F_CURRENT_CPU | (u64) size << 32;
    neteventctx->bytes = size;

    // Set the event type before submitting event.
    neteventctx->eventctx.eventid = event_type;

    // Submit the event.
    long perf_ret = bpf_perf_event_output(ctx, map, flags, neteventctx, sizeof_net_event_context_t());

#ifdef METRICS
    if (map != &events)
        return perf_ret;

    // update event stats
    event_stats_values_t *evt_stat = bpf_map_lookup_elem(&events_stats, &neteventctx->eventctx.eventid);
    if (unlikely(evt_stat == NULL))
        return perf_ret;

    __sync_fetch_and_add(&evt_stat->attempts, 1);
    if (perf_ret < 0)
        __sync_fetch_and_add(&evt_stat->failures, 1);
#endif

    return perf_ret;
}

// Submit a network event.
#define cgroup_skb_submit_event(a, b, c, d) cgroup_skb_submit(&events, a, b, c, d)

// Check if a flag is set in the retval.
#define retval_hasflag(flag) (neteventctx->eventctx.retval & flag) == flag

// Keep track of a flow event if they are enabled and if any policy matched.
// Submit the flow base event so userland can derive the flow events.
statfunc u32 cgroup_skb_submit_flow(struct __sk_buff *ctx,
                                    net_event_context_t *neteventctx,
                                    u32 event_type, u32 size, u32 flow)
{
    netflowvalue_t *netflowvalptr, netflowvalue = {
                                       .last_update = get_current_time_in_ns(),
                                       .direction = flow_unknown,
                                   };

    // Set the current netctx task as the flow task.
    neteventctx->md.flow.host_pid = neteventctx->eventctx.task.host_pid;

    // Set the flow event type in retval.
    neteventctx->eventctx.retval |= flow;

    // Check if the current packet source is the flow initiator.
    bool is_initiator = 0;

    switch (flow) {
        // 1) TCP connection is being established.
        case flow_tcp_begin:
            // Ingress: Remote (src) is sending SYN+ACK: this host (dst) is the initiator.
            if (retval_hasflag(packet_ingress))
                netflowvalue.direction = flow_outgoing;

            // Egress: Host (src) is sending SYN+ACK: remote (dst) host is the initiator.
            if (retval_hasflag(packet_egress))
                netflowvalue.direction = flow_incoming;

            // Invert src/dst: The flowmap src should always be set to flow initiator.
            neteventctx->md.flow = invert_netflow(neteventctx->md.flow);

            // Update the flow map.
            bpf_map_update_elem(&netflowmap, &neteventctx->md.flow, &netflowvalue, BPF_NOEXIST);

            break;

        // 2) TCP connection is being closed/terminated.
        case flow_tcp_end:
            // Any side can close the connection (FIN, RST, etc). Need heuristics.

            // Attempt 01: Try to find the flow using current src/dst.

            for (int n = 0; n < 3; n++) {
                netflowvalptr = bpf_map_lookup_elem(&netflowmap, &neteventctx->md.flow);
                if (!netflowvalptr)
                    continue;
            }

            // FIN could be sent by either side, by both, or by none (RST). Need heuristics.

            if (!netflowvalptr) {
                // Attempt 02: Maybe this packet src wasn't the flow initiator, invert src/dst.
                neteventctx->md.flow = invert_netflow(neteventctx->md.flow);

                for (int n = 0; n < 3; n++) {
                    netflowvalptr = bpf_map_lookup_elem(&netflowmap, &neteventctx->md.flow);
                    if (!netflowvalptr)
                        continue;
                }

                // After first FIN packet is processed the flow is deleted, so the second
                // FIN packet, if ever processed, will not find the flow in the map, and
                // that is ok.
                if (!netflowvalptr)
                    return 0;

                // Flow was found using inverted src/dst: current pkt dst was the flow initiator.
                is_initiator = 0;

            } else {
                // Flow was found using current src/dst: current pkt src was the flow initiator.
                is_initiator = 1;
            }

            // Pick direction from existing flow.
            netflowvalue.direction = netflowvalptr->direction;

            // Inform userland the flow being terminated started by current packet src.
            // This is important so userland knows how to report flow termination correctly.
            if (is_initiator)
                neteventctx->eventctx.retval |= flow_src_initiator;

            // Delete the flow from the map (make sure to delete both sides).
            bpf_map_delete_elem(&netflowmap, &neteventctx->md.flow);
            neteventctx->md.flow = invert_netflow(neteventctx->md.flow);
            bpf_map_delete_elem(&netflowmap, &neteventctx->md.flow);

            break;

        // 3) TODO: UDP flow is considered started when the first packet is sent.
        // case flow_udp_begin:
        //
        // 4) TODO: UDP flow is considered terminated when socket is closed.
        // case flow_udp_end:
        //
        default:
            return 0;
    };

    // Submit the flow base event so userland can derive the flow events.
    cgroup_skb_submit(&events, ctx, neteventctx, event_type, size);

    return 0;
};

// Check if capture event should be submitted, cache the result and submit.
#define cgroup_skb_capture()                                                                       \
    {                                                                                              \
        if (should_submit_net_event(neteventctx, CAP_NET_PACKET)) {                                \
            if (neteventctx->md.captured == 0) {                                                   \
                cgroup_skb_capture_event(ctx, neteventctx, NET_CAPTURE_BASE);                      \
                neteventctx->md.captured = 1;                                                      \
            }                                                                                      \
        }                                                                                          \
    }

// Check if packet should be captured and submit the capture base event.
statfunc u32 cgroup_skb_capture_event(struct __sk_buff *ctx,
                                      net_event_context_t *neteventctx,
                                      u32 event_type)
{
    int zero = 0;

    // Pick the network config map to know the requested capture length.
    netconfig_entry_t *nc = bpf_map_lookup_elem(&netconfig_map, &zero);
    if (nc == NULL)
        return 0;

    // Submit the capture base event.
    return cgroup_skb_submit(&net_cap_events, ctx, neteventctx, event_type, nc->capture_length);
}

//
// Socket creation and socket <=> task context updates
//

// Used to create a file descriptor for a socket. After a file descriptor is
// created, it can be associated with the file operations of the socket, this
// allows a socket to be used with the standard file operations (read, write,
// etc). By having a file descriptor, kernel can keep track of the socket state,
// and also the inode associated to the socket (which is used to link the socket
// to a task).
SEC("kprobe/sock_alloc_file")
int BPF_KPROBE(trace_sock_alloc_file)
{
    // runs every time a socket is created (entry)

    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    if (!is_family_supported(sock))
        return 0;

    if (!is_socket_supported(sock))
        return 0;

    struct entry entry = {0};

    // save args for retprobe
    entry.args[0] = PT_REGS_PARM1(ctx); // struct socket *sock
    entry.args[1] = PT_REGS_PARM2(ctx); // int flags
    entry.args[2] = PT_REGS_PARM2(ctx); // char *dname

    // prepare for kretprobe using entrymap
    u32 host_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&entrymap, &host_tid, &entry, BPF_ANY);

    return 0;
}

// Ditto.
SEC("kretprobe/sock_alloc_file")
int BPF_KRETPROBE(trace_ret_sock_alloc_file)
{
    // runs every time a socket is created (return)

    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // pick from entry from entrymap
    u32 host_tid = p.event->context.task.host_tid;
    struct entry *entry = bpf_map_lookup_elem(&entrymap, &host_tid);
    if (!entry) // no entry == no tracing
        return 0;

    // pick args from entry point's entry
    // struct socket *sock = (void *) entry->args[0];
    // int flags = entry->args[1];
    // char *dname = (void *) entry->args[2];
    struct file *sock_file = (void *) PT_REGS_RC(ctx);

    // cleanup entrymap
    bpf_map_delete_elem(&entrymap, &host_tid);

    if (!sock_file)
        return 0; // socket() failed ?

    u64 inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save context to further create an event when no context exists
    net_task_context_t netctx = {0};
    set_net_task_context(p.event, &netctx);

    // update inodemap correlating inode <=> task
    bpf_map_update_elem(&inodemap, &inode, &netctx, BPF_ANY);

    return 0;
}

SEC("kprobe/security_sk_clone")
int BPF_KPROBE(trace_security_sk_clone)
{
    // When a "sock" is cloned because of a SYN packet, a new "sock" is created
    // and the return value is the new "sock" (not the original one).
    //
    // There is a problem though, the "sock" does not contain a valid "socket"
    // associated to it yet (sk_socket is NULL as this is running with SoftIRQ
    // context). Without a "socket" we also don't have a "file" associated to
    // it, nor an inode associated to that file. This is the way tracee links
    // a network flow (packets) to a task.
    //
    // The only way we can relate this new "sock", just cloned by a kernel
    // thread, to a task, is through the existence of the old "sock" struct,
    // describing the listening socket (one accept() was called for).
    //
    // Then, by knowing the old "sock" (with an existing socket, an existing
    // file, an existing inode), we're able to link this new "sock" to the task
    // we're tracing for the old "sock".
    //
    // In bullets:
    //
    // - tracing a process that has a socket listening for connections.
    // - it receives a SYN packet and a new socket can be created (accept).
    // - a sock (socket descriptor) is created for the socket to be created.
    // - no socket/inode exists yet (sock->sk_socket is NULL).
    // - accept() traces are too late for initial pkts (socked does not exist).
    // - by linking old "sock" to the new "sock" we can relate the task.
    // - some of the initial packets, sometimes with big length, are traced now.
    //
    // More at: https://github.com/aquasecurity/tracee/issues/2739

    struct sock *osock = (void *) PT_REGS_PARM1(ctx);
    struct sock *nsock = (void *) PT_REGS_PARM2(ctx);

    struct socket *osocket = BPF_CORE_READ(osock, sk_socket);
    if (!osocket)
        return 0;

    // obtain old socket inode
    u64 inode = BPF_CORE_READ(osocket, file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // check if old socket family is supported
    if (!is_family_supported(osocket))
        return 0;

    // if the original socket isn't linked to a task, then the newly cloned
    // socket won't need to be linked as well: return in that case

    net_task_context_t *netctx = bpf_map_lookup_elem(&inodemap, &inode);
    if (!netctx)
        return 0; // e.g. task isn't being traced

    u64 nsockptr = (u64) (void *) nsock;

    // link the new "sock" to the old inode, so it can be linked to a task later

    bpf_map_update_elem(&sockmap, &nsockptr, &inode, BPF_ANY);

    return 0;
}

// Associate a socket to a task. This is done by linking the socket inode to the
// task context (inside netctx). This is done when a socket is created, and also
// when a socket is cloned (e.g. when a SYN packet is received and a new socket
// is created).
statfunc u32 update_net_inodemap(struct socket *sock, event_data_t *event)
{
    struct file *sock_file = BPF_CORE_READ(sock, file);
    if (!sock_file)
        return 0;

    u64 inode = BPF_CORE_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save updated context to the inode map (inode <=> task ctx relation)
    net_task_context_t netctx = {0};
    set_net_task_context(event, &netctx);

    bpf_map_update_elem(&inodemap, &inode, &netctx, BPF_ANY);

    return 0;
}

// Called by recv system calls (e.g. recvmsg, recvfrom, recv, ...), or when data
// arrives at the network stack and is destined for a socket, or during socket
// buffer management when kernel is copying data from the network buffer to the
// socket buffer.
SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(trace_security_socket_recvmsg)
{
    struct socket *sock = (void *) PT_REGS_PARM1(ctx);
    if (sock == NULL)
        return 0;
    if (!is_family_supported(sock))
        return 0;
    if (!is_socket_supported(sock))
        return 0;

    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    return update_net_inodemap(sock, p.event);
}

// Called by send system calls (e.g. sendmsg, sendto, send, ...), or when data
// is queued for transmission by the network stack, or during socket buffer
// management when kernel is copying data from the socket buffer to the network
// buffer.
SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(trace_security_socket_sendmsg)
{
    struct socket *sock = (void *) PT_REGS_PARM1(ctx);
    if (sock == NULL)
        return 0;
    if (!is_family_supported(sock))
        return 0;
    if (!is_socket_supported(sock))
        return 0;

    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    return update_net_inodemap(sock, p.event);
}

//
// Socket Ingress/Egress eBPF program loader (right before and right after eBPF)
//

SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(cgroup_bpf_run_filter_skb)
{
    // runs BEFORE the CGROUP/SKB eBPF program

    void *cgrpctxmap = NULL;

    struct sock *sk = (void *) PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (void *) PT_REGS_PARM2(ctx);
    int type = PT_REGS_PARM3(ctx);

    if (!sk || !skb)
        return 0;

    s64 packet_dir_flag; // used later to set packet direction flag
    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
            cgrpctxmap = &cgrpctxmap_in;
            packet_dir_flag = packet_ingress;
            break;
        case BPF_CGROUP_INET_EGRESS:
            cgrpctxmap = &cgrpctxmap_eg;
            packet_dir_flag = packet_egress;
            break;
        default:
            return 0; // other attachment type, return fast
    }

    struct sock_common *common = (void *) sk;
    u8 family = BPF_CORE_READ(common, skc_family);

    switch (family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // return fast for unsupported socket families
    }

    //
    // EVENT CONTEXT (from current task, might be a kernel context/thread)
    //

    u32 zero = 0;
    event_data_t *e = bpf_map_lookup_elem(&net_heap_event, &zero);
    if (unlikely(e == NULL))
        return 0;

    program_data_t p = {};
    p.scratch_idx = 1;
    p.event = e;
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    bool mightbecloned = false; // cloned sock structs come from accept()

    // obtain the socket inode using current "sock" structure

    u64 inode = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    if (inode == 0)
        mightbecloned = true; // kernel threads might have zero inode

    struct net_task_context *netctx;

    // obtain the task ctx using the obtained socket inode

    if (!mightbecloned) {
        // pick network context from the inodemap (inode <=> task)
        netctx = bpf_map_lookup_elem(&inodemap, &inode);
        if (!netctx)
            mightbecloned = true; // e.g. task isn't being traced
    }

    // If inode is zero, or task context couldn't be found, try to find it using
    // the "sock" pointer from sockmap (this sock struct might be new, just
    // cloned, and a socket might not exist yet, but the sockmap is likely to
    // have the entry). Check trace_security_sk_clone() for more details.

    if (mightbecloned) {
        // pick network context from the sockmap (new sockptr <=> old inode <=> task)
        u64 skptr = (u64) (void *) sk;
        u64 *o = bpf_map_lookup_elem(&sockmap, &skptr);
        if (o == 0)
            return 0;
        u64 oinode = *o;

        // with the old inode, find the netctx for the task
        netctx = bpf_map_lookup_elem(&inodemap, &oinode);
        if (!netctx)
            return 0; // old inode wasn't being traced as well

        // update inodemap w/ new inode <=> task context (faster path next time)
        bpf_map_update_elem(&inodemap, &oinode, netctx, BPF_ANY);
    }

// CHECK: should_submit_net_event() for more info
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"

    //
    // PREPARE SKG PROGRAM EVENT CONTEXT (cgrpctxmap value)
    //

    // Prepare [event_context_t][args1,arg2,arg3...] to be sent by cgroup/skb
    // program. The [...] part of the event can't use existing per-cpu submit
    // buffer helpers because the time in between this kprobe fires and the
    // cgroup/skb program runs might be suffer a preemption.

    net_event_context_t neteventctx = {0}; // to be sent by cgroup/skb program
    event_context_t *eventctx = &neteventctx.eventctx;

#pragma clang diagnostic pop

    // copy orig task ctx (from the netctx) to event ctx and build the rest
    __builtin_memcpy(&eventctx->task, &netctx->taskctx, sizeof(task_context_t));
    eventctx->ts = p.event->context.ts;                     // copy timestamp from current ctx
    neteventctx.argnum = 1;                                 // 1 argument (add more if needed)
    eventctx->eventid = NET_PACKET_IP;                      // will be changed in skb program
    eventctx->stack_id = 0;                                 // no stack trace
    eventctx->processor_id = p.event->context.processor_id; // copy from current ctx
    eventctx->policies_version = netctx->policies_version;  // pick policies_version from net ctx
    eventctx->matched_policies = netctx->matched_policies;  // pick matched_policies from net ctx
    eventctx->syscall = NO_SYSCALL;                         // ingress has no orig syscall
    if (type == BPF_CGROUP_INET_EGRESS)
        eventctx->syscall = netctx->syscall; // egress does have an orig syscall

    //
    // SKB PROGRAM CONTEXT INDEXER (cgrpctxmap key)
    //

    u32 l3_size = 0;
    nethdrs hdrs = {0}, *nethdrs = &hdrs;

    // inform userland about protocol family (for correct L3 header parsing)...
    switch (family) {
        case PF_INET:
            eventctx->retval |= family_ipv4;
            l3_size = bpf_core_type_size(struct iphdr);
            break;
        case PF_INET6:
            eventctx->retval |= family_ipv6;
            l3_size = bpf_core_type_size(struct ipv6hdr);
            break;
        default:
            return 1;
    }

    // ... and packet direction(ingress/egress) ...
    eventctx->retval |= packet_dir_flag;
    // ... through event ctx ret val.

    // Read packet headers from the skb.
    void *data_ptr = BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
    bpf_core_read(nethdrs, l3_size, data_ptr);

    // Prepare the inter-eBPF-program indexer.
    indexer_t indexer = {0};
    indexer.ts = BPF_CORE_READ(skb, tstamp);

    u8 proto = 0;

    // Parse the packet layer 3 headers.
    switch (family) {
        case PF_INET:
            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

            if (nethdrs->iphdrs.iphdr.ihl > 5) { // re-read IP header if needed
                l3_size -= bpf_core_type_size(struct iphdr);
                l3_size += nethdrs->iphdrs.iphdr.ihl * 4;
                bpf_core_read(nethdrs, l3_size, data_ptr);
            }

            proto = nethdrs->iphdrs.iphdr.protocol;
            switch (proto) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                    break;
                default:
                    return 1; // ignore other protocols
            }

            // Update inter-eBPF-program indexer with IPv4 header items.
            indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
            indexer.src.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
            indexer.dst.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
            break;

        case PF_INET6:
            // TODO: dual-stack IP implementation unsupported for now
            // https://en.wikipedia.org/wiki/IPv6_transition_mechanism
            if (nethdrs->iphdrs.ipv6hdr.version != 6) // IPv6
                return 1;

            proto = nethdrs->iphdrs.ipv6hdr.nexthdr;
            switch (proto) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_ICMPV6:
                    break;
                default:
                    return 1; // ignore other protocols
            }

            // Update inter-eBPF-program indexer with IPv6 header items.
            __builtin_memcpy(&indexer.src.in6_u, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
            __builtin_memcpy(&indexer.dst.in6_u, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
            break;

        default:
            return 1;
    }

    //
    // LINK CONTENT INDEXER TO EVENT CONTEXT
    //

    neteventctx.bytes = 0; // event arg size: no payload by default (changed inside skb prog)

    // initialize task context before submit since it will not be available when
    // submitting the network event.
    init_task_context(&eventctx->task, p.event->task, p.config->options);

    // TODO: log collisions
    bpf_map_update_elem(cgrpctxmap, &indexer, &neteventctx, BPF_NOEXIST);

    return 0;
}

//
// SKB eBPF programs
//

statfunc u32 cgroup_skb_generic(struct __sk_buff *ctx, void *cgrpctxmap)
{
    // IMPORTANT: runs for EVERY packet of tasks belonging to root cgroup

    switch (ctx->family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // PF_INET and PF_INET6 only
    }

    // HANDLE SOCKET FAMILY

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

    nethdrs hdrs = {0}, *nethdrs = &hdrs;

    void *dest;

    u32 size = 0;
    u32 family = ctx->family;

    switch (family) {
        case PF_INET:
            dest = &nethdrs->iphdrs.iphdr;
            size = bpf_core_type_size(struct iphdr);
            break;
        case PF_INET6:
            dest = &nethdrs->iphdrs.ipv6hdr;
            size = bpf_core_type_size(struct ipv6hdr);
            break;
        default:
            return 1; // verifier
    }

    // load layer 3 headers (for cgrpctxmap key/indexer)

    if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1))
        return 1;

    //
    // IGNORE UNSUPPORTED PROTOCOLS, CREATE INDEXER TO OBTAIN EVENT
    //

    indexer_t indexer = {0};
    indexer.ts = ctx->tstamp;

    u32 ihl = 0;
    switch (family) {
        case PF_INET:
            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

            ihl = nethdrs->iphdrs.iphdr.ihl;
            if (ihl > 5) { // re-read IPv4 header if needed
                size -= bpf_core_type_size(struct iphdr);
                size += ihl * 4;
                bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1);
            }

            switch (nethdrs->iphdrs.iphdr.protocol) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                    break;
                default:
                    return 1; // unsupported proto
            }

            // add IPv4 header items to indexer
            indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
            indexer.src.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
            indexer.dst.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
            break;

        case PF_INET6:
            // TODO: dual-stack IP implementation unsupported for now
            // https://en.wikipedia.org/wiki/IPv6_transition_mechanism
            if (nethdrs->iphdrs.ipv6hdr.version != 6) // IPv6
                return 1;

            switch (nethdrs->iphdrs.ipv6hdr.nexthdr) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_ICMPV6:
                    break;
                default:
                    return 1; // unsupported proto
            }

            // add IPv6 header items to indexer
            __builtin_memcpy(&indexer.src.in6_u, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
            __builtin_memcpy(&indexer.dst.in6_u, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
            break;

        default:
            return 1; // verifier
    }

    net_event_context_t *neteventctx;
    neteventctx = bpf_map_lookup_elem(cgrpctxmap, &indexer); // obtain event context
    if (!neteventctx) {
        // 1. kthreads receiving ICMP and ICMPv6 (e.g dest unreach)
        // 2. tasks not being traced
        // 3. unknown (yet) sockets (need egress packet to link task and inode)
        // ...
        return 1;
    }

    neteventctx->md.header_size = size; // add header size to offset

    u32 ret = CGROUP_SKB_HANDLE(proto);

    bpf_map_delete_elem(cgrpctxmap, &indexer); // cleanup

    return ret; // important for network blocking
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx, &cgrpctxmap_in);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx, &cgrpctxmap_eg);
}

//
// Network Protocol Events Logic
//

//
// SUPPORTED L3 NETWORK PROTOCOLS (ip, ipv6) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto)
{
    void *dest = NULL;
    u32 prev_hdr_size = neteventctx->md.header_size;
    u32 size = 0;
    u8 next_proto = 0;

    // NOTE: might block IP and IPv6 here if needed (return 0)

    switch (ctx->family) {
        case PF_INET:
            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

            next_proto = nethdrs->iphdrs.iphdr.protocol;
            switch (next_proto) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = bpf_core_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = bpf_core_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMP:
                    dest = &nethdrs->protohdrs.icmphdr;
                    size = 0; // will be added later, last function
                    break;
                default:
                    return 1; // other protocols are not an error
            }

            // Update the network flow map indexer with the packet headers.
            neteventctx->md.flow.src.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
            neteventctx->md.flow.dst.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
            break;

        case PF_INET6:
            // TODO: dual-stack IP implementation unsupported for now
            // https://en.wikipedia.org/wiki/IPv6_transition_mechanism
            if (nethdrs->iphdrs.ipv6hdr.version != 6) // IPv6
                return 1;

            next_proto = nethdrs->iphdrs.ipv6hdr.nexthdr;
            switch (next_proto) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = bpf_core_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = bpf_core_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMPV6:
                    dest = &nethdrs->protohdrs.icmp6hdr;
                    size = 0; // will be added later, last function
                    break;
                default:
                    return 1; // other protocols are not an error
            }

            // Update the network flow map indexer with the packet headers.
            __builtin_memcpy(&neteventctx->md.flow.src, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
            __builtin_memcpy(&neteventctx->md.flow.dst, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
            break;

        default:
            return 1; // verifier needs as this was already checked
    }

    // Update the network flow map indexer with the packet headers.
    neteventctx->md.flow.proto = next_proto;

    if (!dest)
        return 1; // satisfy verifier for clang-12 generated binaries

    // fastpath: submit the raw packet and IP base events

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_RAW))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_RAW, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_IP, HEADERS);

    // fastpath: capture all packets if filtered pcap-option is not set

    u32 zero = 0;
    netconfig_entry_t *nc = bpf_map_lookup_elem(&netconfig_map, &zero);
    if (nc == NULL)
        return 0;

    if (!(nc->capture_options & NET_CAP_OPT_FILTERED))
        cgroup_skb_capture(); // will avoid extra lookups further if not needed

    // Update the network event context with payload size.
    neteventctx->md.header_size += size;

    // Load the next protocol header.
    if (size) {
        if (bpf_skb_load_bytes_relative(ctx, prev_hdr_size, dest, size, BPF_HDR_START_NET))
            return 1;
    }

    // Call the next protocol handler.
    switch (next_proto) {
        case IPPROTO_TCP:
            return CGROUP_SKB_HANDLE(proto_tcp);
        case IPPROTO_UDP:
            return CGROUP_SKB_HANDLE(proto_udp);
        case IPPROTO_ICMP:
            return CGROUP_SKB_HANDLE(proto_icmp);
        case IPPROTO_ICMPV6:
            return CGROUP_SKB_HANDLE(proto_icmpv6);
        default:
            return 1; // verifier needs
    }

    // TODO: If cmdline is tracing net_packet_ipv6 only, then the ipv4 packets
    //       shouldn't be added to the pcap file. Filters will have to be
    //       applied to the capture pipeline to obey derived events only
    //       filters + capture.

    // Capture IPv4/IPv6 packets (filtered).
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_capture();

    return 1;
}

//
// GUESS L7 NETWORK PROTOCOLS (http, dns, etc)
//

// when guessing by src/dst ports, declare at network.h

// when guessing through l7 layer, here

statfunc int net_l7_is_http(struct __sk_buff *skb, u32 l7_off)
{
    char http_min_str[http_min_len];
    __builtin_memset((void *) &http_min_str, 0, sizeof(char) * http_min_len);

    // load first http_min_len bytes from layer 7 in packet.
    if (bpf_skb_load_bytes(skb, l7_off, http_min_str, http_min_len) < 0) {
        return 0; // failed loading data into http_min_str - return.
    }

    // check if HTTP response
    if (strncmp("HTTP/", http_min_str, 5) == 0) {
        return proto_http_resp;
    }

    // check if HTTP request
    if (strncmp("GET ", http_min_str, 4) == 0 ||
        strncmp("POST ", http_min_str, 5) == 0 ||
        strncmp("PUT ", http_min_str, 4) == 0 ||
        strncmp("DELETE ", http_min_str, 7) == 0 ||
        strncmp("HEAD ", http_min_str, 5) == 0) {
        return proto_http_req;
    }

    return 0;
}

//
// SUPPORTED L4 NETWORK PROTOCOL (tcp, udp, icmp) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp)
{
    // Check TCP header flag for dynamic header size (TCP: data offset flag).

    if (nethdrs->protohdrs.tcphdr.doff > 5) { // offset flag set
        u32 doff = nethdrs->protohdrs.tcphdr.doff * (32 / 8);
        neteventctx->md.header_size -= bpf_core_type_size(struct tcphdr);
        neteventctx->md.header_size += doff;
    }

    // Pick src/dst ports.

    u16 srcport = bpf_ntohs(nethdrs->protohdrs.tcphdr.source);
    u16 dstport = bpf_ntohs(nethdrs->protohdrs.tcphdr.dest);

    // Update the network flow map indexer with the packet headers.
    neteventctx->md.flow.srcport = srcport;
    neteventctx->md.flow.dstport = dstport;

    // Check if TCP flow needs to be submitted (only headers).

    bool is_rst = nethdrs->protohdrs.tcphdr.rst;
    bool is_syn = nethdrs->protohdrs.tcphdr.syn;
    bool is_ack = nethdrs->protohdrs.tcphdr.ack;
    bool is_fin = nethdrs->protohdrs.tcphdr.fin;

    // Has TCP flow started ?
    if ((is_syn & is_ack) && should_submit_flow_event(neteventctx))
        cgroup_skb_submit_flow(ctx, neteventctx, NET_FLOW_BASE, HEADERS, flow_tcp_begin);

    // Has TCP flow ended ?
    if ((is_fin || is_rst) && should_submit_flow_event(neteventctx))
        cgroup_skb_submit_flow(ctx, neteventctx, NET_FLOW_BASE, HEADERS, flow_tcp_end);

    // Submit TCP base event if needed (only headers)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_TCP, HEADERS);

    // Fastpath: return if no other L7 network events.

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS) &&
        !should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        goto capture;

    // Guess layer 7 protocols by src/dst ports ...

    switch (srcport < dstport ? srcport : dstport) {
        case TCP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_tcp_dns);
    }

    // ... and by analyzing payload.

    int http_proto = net_l7_is_http(ctx, neteventctx->md.header_size);
    if (http_proto) {
        neteventctx->eventctx.retval |= http_proto;
        return CGROUP_SKB_HANDLE(proto_tcp_http);
    }

    // ... continue with net_l7_is_protocol_xxx

capture:
    // Capture IP or TCP packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_TCP)) {
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block TCP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp)
{
    // Submit UDP base event if needed (only headers).

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_UDP, HEADERS);

    // Fastpath: return if no other L7 network events.

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS) &&
        !should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        goto capture;

    // Guess layer 7 protocols ...

    u16 source = bpf_ntohs(nethdrs->protohdrs.udphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.udphdr.dest);

    // ... by src/dst ports

    switch (source < dest ? source : dest) {
        case UDP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_udp_dns);
    }

    // ... by analyzing payload
    // ...

    // ... continue with net_l7_is_protocol_xxx

capture:
    // Capture IP or UDP packets (filtered).
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_UDP)) {
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block UDP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_icmp)
{
    // submit ICMP base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_ICMP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_ICMP, FULL);

    // capture ip or icmp packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_ICMP)) {
        neteventctx->md.header_size = ctx->len; // full ICMP header
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block ICMP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_icmpv6)
{
    // submit ICMPv6 base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_ICMPV6))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_ICMPV6, FULL);

    // capture ip or icmpv6 packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_ICMPV6)) {
        neteventctx->md.header_size = ctx->len; // full ICMPv6 header
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block ICMPv6 here if needed (return 0)
}

//
// SUPPORTED L7 NETWORK PROTOCOL (dns) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns)
{
    // submit DNS base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_DNS, FULL);

    // capture DNS-TCP, TCP or IP packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_TCP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_DNS)) {
        neteventctx->md.header_size = ctx->len; // full dns header
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block DNS here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns)
{
    // submit DNS base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_DNS, FULL);

    // capture DNS-UDP, UDP or IP packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_UDP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_DNS)) {
        neteventctx->md.header_size = ctx->len; // full dns header
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block DNS here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_http)
{
    // submit HTTP base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_HTTP, FULL);

    // capture HTTP-TCP, TCP or IP packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_TCP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_HTTP)) {
        cgroup_skb_capture(); // http header is dyn, do not change header_size
    }

    return 1; // NOTE: might block HTTP here if needed (return 0)
}

// clang-format on

//
// Control Plane Programs
//
// Control Plane programs are almost duplicate programs of select events which we send as direct
// signals to tracee in a separate buffer. This is done to mitigate the consenquences of losing
// these events in the main perf buffer.
//

// Containers Lifecyle

SEC("raw_tracepoint/cgroup_mkdir_signal")
int cgroup_mkdir_signal(struct bpf_raw_tracepoint_args *ctx)
{
    u32 zero = 0;
    config_entry_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(cfg == NULL))
        return 0;
    controlplane_signal_t *signal = init_controlplane_signal(SIGNAL_CGROUP_MKDIR);
    if (unlikely(signal == NULL))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((cfg->options & OPT_CGROUP_V1) && (cfg->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update) {
        // Assume this is a new container. If not, userspace code will delete this entry
        u8 state = CONTAINER_CREATED;
        bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
    }

    save_to_submit_buf(&signal->args_buf, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&signal->args_buf, path, 1);
    save_to_submit_buf(&signal->args_buf, &hierarchy_id, sizeof(u32), 2);
    signal_perf_submit(ctx, signal);

    return 0;
}

SEC("raw_tracepoint/cgroup_rmdir_signal")
int cgroup_rmdir_signal(struct bpf_raw_tracepoint_args *ctx)
{
    u32 zero = 0;
    config_entry_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(cfg == NULL))
        return 0;
    controlplane_signal_t *signal = init_controlplane_signal(SIGNAL_CGROUP_RMDIR);
    if (unlikely(signal == NULL))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((cfg->options & OPT_CGROUP_V1) && (cfg->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update)
        bpf_map_delete_elem(&containers_map, &cgroup_id_lsb);

    save_to_submit_buf(&signal->args_buf, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&signal->args_buf, path, 1);
    save_to_submit_buf(&signal->args_buf, &hierarchy_id, sizeof(u32), 2);
    signal_perf_submit(ctx, signal);

    return 0;
}

// Processes Lifecycle

// NOTE: sched_process_fork is called by kernel_clone(), which is executed during
//       clone() calls as well, not only fork(). This means that sched_process_fork()
//       is also able to pick the creation of LWPs through clone().

SEC("raw_tracepoint/sched_process_fork")
int sched_process_fork_signal(struct bpf_raw_tracepoint_args *ctx)
{
    controlplane_signal_t *signal = init_controlplane_signal(SIGNAL_SCHED_PROCESS_FORK);
    if (unlikely(signal == NULL))
        return 0;

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];
    struct task_struct *leader = get_leader_task(child);
    struct task_struct *parent_process = get_leader_task(get_parent_task(leader));

    // In the Linux kernel:
    //
    // Every task (a process or a thread) is represented by a `task_struct`:
    //
    // - `pid`: Inside the `task_struct`, there's a field called `pid`. This is a unique identifier
    //   for every task, which can be thought of as the thread ID (TID) from a user space
    //   perspective. Every task, whether it's the main thread of a process or an additional thread,
    //   has a unique `pid`.
    //
    // - `tgid` (Thread Group ID): This field in the `task_struct` is used to group threads from the
    //   same process. For the main thread of a process, the `tgid` is the same as its `pid`. For
    //   other threads created by that process, the `tgid` matches the `pid` of the main thread.
    //
    // In userspace:
    //
    // - `getpid()` returns the TGID, effectively the traditional process ID.
    // - `gettid()` returns the PID (from the `task_struct`), effectively the thread ID.
    //
    // This design in the Linux kernel leads to a unified handling of processes and threads. In the
    // kernel's view, every thread is a task with potentially shared resources, but each has a
    // unique PID. In user space, the distinction is made where processes have a unique PID, and
    // threads within those processes have unique TIDs.

    // Summary:
    // userland pid = kernel tgid
    // userland tgid = kernel pid

    // The event timestamp, so process tree info can be changelog'ed.
    u64 timestamp = get_current_time_in_ns();
    save_to_submit_buf(&signal->args_buf, &timestamp, sizeof(u64), 0);

    // Parent information.
    u64 parent_start_time = get_task_start_time(parent);
    int parent_pid = get_task_host_tgid(parent);
    int parent_tid = get_task_host_pid(parent);
    int parent_ns_pid = get_task_ns_tgid(parent);
    int parent_ns_tid = get_task_ns_pid(parent);

    // Child information.
    u64 child_start_time = get_task_start_time(child);
    int child_pid = get_task_host_tgid(child);
    int child_tid = get_task_host_pid(child);
    int child_ns_pid = get_task_ns_tgid(child);
    int child_ns_tid = get_task_ns_pid(child);

    // Parent Process information: Go up in hierarchy until parent is process.
    u64 parent_process_start_time = get_task_start_time(parent_process);
    int parent_process_pid = get_task_host_tgid(parent_process);
    int parent_process_tid = get_task_host_pid(parent_process);
    int parent_process_ns_pid = get_task_ns_tgid(parent_process);
    int parent_process_ns_tid = get_task_ns_pid(parent_process);

    // Leader information.
    u64 leader_start_time = get_task_start_time(leader);
    int leader_pid = get_task_host_tgid(leader);
    int leader_tid = get_task_host_pid(leader);
    int leader_ns_pid = get_task_ns_tgid(leader);
    int leader_ns_tid = get_task_ns_pid(leader);

    // Parent (might be a thread or a process).
    save_to_submit_buf(&signal->args_buf, (void *) &parent_tid, sizeof(int), 1);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_ns_tid, sizeof(int), 2);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_pid, sizeof(int), 3);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_ns_pid, sizeof(int), 4);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_start_time, sizeof(u64), 5);

    // Child (might be a thread or a process, sched_process_fork trace is calle by clone() also).
    save_to_submit_buf(&signal->args_buf, (void *) &child_tid, sizeof(int), 6);
    save_to_submit_buf(&signal->args_buf, (void *) &child_ns_tid, sizeof(int), 7);
    save_to_submit_buf(&signal->args_buf, (void *) &child_pid, sizeof(int), 8);
    save_to_submit_buf(&signal->args_buf, (void *) &child_ns_pid, sizeof(int), 9);
    save_to_submit_buf(&signal->args_buf, (void *) &child_start_time, sizeof(u64), 10);

    // Parent Process: always a real process (might be the same as Parent if it is a real process).
    save_to_submit_buf(&signal->args_buf, (void *) &parent_process_tid, sizeof(int), 11);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_process_ns_tid, sizeof(int), 12);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_process_pid, sizeof(int), 13);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_process_ns_pid, sizeof(int), 14);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_process_start_time, sizeof(u64), 15);

    // Leader: always a real process (might be the same as the Child if child is a real process).
    save_to_submit_buf(&signal->args_buf, (void *) &leader_tid, sizeof(int), 16);
    save_to_submit_buf(&signal->args_buf, (void *) &leader_ns_tid, sizeof(int), 17);
    save_to_submit_buf(&signal->args_buf, (void *) &leader_pid, sizeof(int), 18);
    save_to_submit_buf(&signal->args_buf, (void *) &leader_ns_pid, sizeof(int), 19);
    save_to_submit_buf(&signal->args_buf, (void *) &leader_start_time, sizeof(u64), 20);

    signal_perf_submit(ctx, signal);

    return 0;
}

// clang-format off

SEC("raw_tracepoint/sched_process_exec")
int sched_process_exec_signal(struct bpf_raw_tracepoint_args *ctx)
{
    controlplane_signal_t *signal = init_controlplane_signal(SIGNAL_SCHED_PROCESS_EXEC);
    if (unlikely(signal == NULL))
        return 0;

    // Hashes

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    if (task == NULL)
        return -1;
    struct task_struct *leader = get_leader_task(task);
    struct task_struct *parent = get_leader_task(get_parent_task(leader));

    // The hash is always calculated with "task_struct->pid + start_time".
    u32 task_hash = hash_task_id(get_task_host_pid(task), get_task_start_time(task));
    u32 parent_hash = hash_task_id(get_task_host_pid(parent), get_task_start_time(parent));
    u32 leader_hash = hash_task_id(get_task_host_pid(leader), get_task_start_time(leader));

    // The event timestamp, so process tree info can be changelog'ed.
    u64 timestamp = get_current_time_in_ns();
    save_to_submit_buf(&signal->args_buf, &timestamp, sizeof(u64), 0);

    save_to_submit_buf(&signal->args_buf, (void *) &task_hash, sizeof(u32), 1);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_hash, sizeof(u32), 2);
    save_to_submit_buf(&signal->args_buf, (void *) &leader_hash, sizeof(u32), 3);

    // Exec logic

    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    if (bprm == NULL)
        return -1;

    // Pick the interpreter path from the proc_info map, which is set by the "load_elf_phdrs".
    u32 host_pid = get_task_host_tgid(task);
    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &host_pid);
    if (proc_info == NULL) {
        proc_info = init_proc_info(host_pid, 0);
        if (unlikely(proc_info == NULL)) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }
    }

    struct file *file = get_file_ptr_from_bprm(bprm);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
    const char *filename = get_binprm_filename(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);
    umode_t inode_mode = get_inode_mode_from_file(file);

    save_str_to_buf(&signal->args_buf, (void *) filename, 4);                   // executable name
    save_str_to_buf(&signal->args_buf, file_path, 5);                           // executable path
    save_to_submit_buf(&signal->args_buf, &s_dev, sizeof(dev_t), 6);            // device number
    save_to_submit_buf(&signal->args_buf, &inode_nr, sizeof(unsigned long), 7); // inode number
    save_to_submit_buf(&signal->args_buf, &ctime, sizeof(u64), 8);              // creation time
    save_to_submit_buf(&signal->args_buf, &inode_mode, sizeof(umode_t), 9);     // inode mode

    // The proc_info interpreter field is set by "load_elf_phdrs" kprobe program.
    save_str_to_buf(&signal->args_buf, &proc_info->interpreter.pathname, 10);                    // interpreter path
    save_to_submit_buf(&signal->args_buf, &proc_info->interpreter.id.device, sizeof(dev_t), 11); // interpreter device number
    save_to_submit_buf(&signal->args_buf, &proc_info->interpreter.id.inode, sizeof(u64), 12);    // interpreter inode number
    save_to_submit_buf(&signal->args_buf, &proc_info->interpreter.id.ctime, sizeof(u64), 13);    // interpreter creation time

    struct mm_struct *mm = get_mm_from_task(task); // bprm->mm is null here, but task->mm is not

    unsigned long arg_start, arg_end;
    arg_start = get_arg_start_from_mm(mm);
    arg_end = get_arg_end_from_mm(mm);
    int argc = get_argc_from_bprm(bprm);

    struct file *stdin_file = get_struct_file_from_fd(0);
    unsigned short stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
    void *stdin_path = get_path_str(__builtin_preserve_access_index(&stdin_file->f_path));
    const char *interp = get_binprm_interp(bprm);

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD)
        invoked_from_kernel = 1;

    save_args_str_arr_to_buf(&signal->args_buf, (void *) arg_start, (void *) arg_end, argc, 14); // argv
    save_str_to_buf(&signal->args_buf, (void *) interp, 15);                                     // interp
    save_to_submit_buf(&signal->args_buf, &stdin_type, sizeof(unsigned short), 16);              // stdin type
    save_str_to_buf(&signal->args_buf, stdin_path, 17);                                          // stdin path
    save_to_submit_buf(&signal->args_buf, &invoked_from_kernel, sizeof(int), 18);                // invoked from kernel ?

    signal_perf_submit(ctx, signal);

    return 0;
}

// clang-format on

SEC("raw_tracepoint/sched_process_exit")
int sched_process_exit_signal(struct bpf_raw_tracepoint_args *ctx)
{
    controlplane_signal_t *signal = init_controlplane_signal(SIGNAL_SCHED_PROCESS_EXIT);
    if (unlikely(signal == NULL))
        return 0;

    // Hashes

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL)
        return -1;
    struct task_struct *leader = get_leader_task(task);
    struct task_struct *parent = get_leader_task(get_parent_task(leader));

    // The hash is always calculated with "task_struct->pid + start_time".
    u32 task_hash = hash_task_id(get_task_host_pid(task), get_task_start_time(task));
    u32 parent_hash = hash_task_id(get_task_host_pid(parent), get_task_start_time(parent));
    u32 leader_hash = hash_task_id(get_task_host_pid(leader), get_task_start_time(leader));

    // The event timestamp, so process tree info can be changelog'ed.
    u64 timestamp = get_current_time_in_ns();
    save_to_submit_buf(&signal->args_buf, &timestamp, sizeof(u64), 0);

    save_to_submit_buf(&signal->args_buf, (void *) &task_hash, sizeof(u32), 1);
    save_to_submit_buf(&signal->args_buf, (void *) &parent_hash, sizeof(u32), 2);
    save_to_submit_buf(&signal->args_buf, (void *) &leader_hash, sizeof(u32), 3);

    // Exit logic.

    bool group_dead = false;
    struct signal_struct *s = BPF_CORE_READ(task, signal);
    atomic_t live = BPF_CORE_READ(s, live);

    if (live.counter == 0)
        group_dead = true;

    long exit_code = get_task_exit_code(task);

    save_to_submit_buf(&signal->args_buf, (void *) &exit_code, sizeof(long), 4);
    save_to_submit_buf(&signal->args_buf, (void *) &group_dead, sizeof(bool), 5);

    signal_perf_submit(ctx, signal);

    return 0;
}

// END OF Control Plane Programs

// Tests

SEC("kprobe/empty_kprobe")
int BPF_KPROBE(empty_kprobe)
{
    return 0;
}

SEC("raw_tracepoint/exec_test")
int tracepoint__exec_test(struct bpf_raw_tracepoint_args *ctx)
{
    // Check if test file was executed
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    if (bprm == NULL)
        return -1;
    struct file *file = get_file_ptr_from_bprm(bprm);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
    if (file_path == NULL || strncmp("/tmp/test", file_path, 9) != 0)
        return 0;

    // Submit all test events
    int ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx, NO_EVENT_SUBMIT))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    if (!reset_event(p.event, EXEC_TEST))
        return 0;
    if (evaluate_scope_filters(&p))
        ret |= events_perf_submit(&p, 0);

    if (!reset_event(p.event, TEST_MISSING_KSYMBOLS))
        return 0;
    if (evaluate_scope_filters(&p))
        ret |= events_perf_submit(&p, 0);

    if (!reset_event(p.event, TEST_FAILED_ATTACH))
        return 0;
    if (evaluate_scope_filters(&p))
        ret |= events_perf_submit(&p, 0);

    return 0;
}
