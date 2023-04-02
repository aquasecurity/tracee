// +build ignore

// Note: This file is licenced differently from the rest of the project
// SPDX-License-Identifier: GPL-2.0
// Copyright (C) Aqua Security inc.

#ifndef CORE
    #include <uapi/linux/magic.h>
    #include <uapi/linux/ptrace.h>
    #include <uapi/linux/in.h>
    #include <uapi/linux/in6.h>
    #include <uapi/linux/uio.h>
    #include <uapi/linux/un.h>
    #include <uapi/linux/utsname.h>
    #include <uapi/linux/stat.h>
    #include <linux/binfmts.h>
    #include <linux/cred.h>
    #include <linux/sched.h>
    #include <linux/signal.h>
    #include <linux/fs.h>
    #include <linux/mm_types.h>
    #include <linux/time.h>
    #include <linux/mount.h>
    #include <linux/nsproxy.h>
    #include <linux/ns_common.h>
    #include <linux/pid_namespace.h>
    #include <linux/ipc_namespace.h>
    #include <net/net_namespace.h>
    #include <linux/utsname.h>
    #include <linux/cgroup.h>
    #include <linux/security.h>
    #include <linux/socket.h>
    #include <linux/version.h>
    #include <linux/fdtable.h>
    #define KBUILD_MODNAME "tracee"
    #include <net/af_unix.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <net/ipv6.h>
    #include <net/tcp_states.h>
    #include <linux/ipv6.h>
    #include <uapi/linux/icmp.h>
    #include <uapi/linux/icmpv6.h>

    #include <uapi/linux/bpf.h>
    #include <linux/bpf.h>
    #include <linux/kconfig.h>
    #include <linux/version.h>

    #include <linux/if_ether.h>
    #include <linux/in.h>
    #include <linux/ip.h>
    #include <linux/ipv6.h>
    #include <linux/pkt_cls.h>
    #include <linux/tcp.h>

    #if defined(CONFIG_FUNCTION_TRACER)
        #define CC_USING_FENTRY
    #endif

    #include <linux/perf_event.h>
    #include <linux/kprobes.h>
    #include <linux/uprobes.h>
    #include <linux/trace_events.h>
    #include <linux/bpf_verifier.h>

    #include "missing_noncore_definitions.h"

#else
    // CO:RE is enabled
    #include <vmlinux.h>
    #include <missing_definitions.h>

#endif

#undef container_of
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "types.h"
#include "common/arch.h"
#include "common/arguments.h"
#include "common/binprm.h"
#include "common/buffer.h"
#include "common/cgroups.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filesystem.h"
#include "common/filtering.h"
#include "common/kconfig.h"
#include "common/ksymbols.h"
#include "common/logging.h"
#include "common/memory.h"
#include "common/network.h"
#include "common/probes.h"
#include "common/bpf_prog.h"

char LICENSE[] SEC("license") = "GPL";
#ifndef CORE
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
#endif

// SYSCALL HOOKS -----------------------------------------------------------------------------------

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
        u32 pid = pid_tgid >> 32;
        task_info = init_task_info(tid, pid, NULL);
        if (unlikely(task_info == NULL)) {
            return 0;
        }
    }

    syscall_data_t *sys = &(task_info->syscall_data);
    sys->id = ctx->args[1];

    if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)) {
        struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

        if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
            sys->args.args[0] = READ_KERN(regs->bx);
            sys->args.args[1] = READ_KERN(regs->cx);
            sys->args.args[2] = READ_KERN(regs->dx);
            sys->args.args[3] = READ_KERN(regs->si);
            sys->args.args[4] = READ_KERN(regs->di);
            sys->args.args[5] = READ_KERN(regs->bp);
#endif // bpf_target_x86
        } else {
            sys->args.args[0] = READ_KERN(PT_REGS_PARM1(regs));
            sys->args.args[1] = READ_KERN(PT_REGS_PARM2(regs));
            sys->args.args[2] = READ_KERN(PT_REGS_PARM3(regs));
#if defined(bpf_target_x86)
            // x86-64: r10 used instead of rcx (4th param to a syscall)
            sys->args.args[3] = READ_KERN(regs->r10);
#else
            sys->args.args[3] = READ_KERN(PT_REGS_PARM4(regs));
#endif
            sys->args.args[4] = READ_KERN(PT_REGS_PARM5(regs));
            sys->args.args[5] = READ_KERN(PT_REGS_PARM6(regs));
        }
    } else {
        bpf_probe_read(sys->args.args, sizeof(6 * sizeof(u64)), (void *) ctx->args);
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
        sys->ts = bpf_ktime_get_ns();
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (p.config->options & OPT_TRANSLATE_FD_FILEPATH && has_syscall_fd_arg(sys->id)) {
        // Process filepath related to fd argument
        uint fd_num = get_syscall_fd_num_from_arg(sys->id, &sys->args);
        struct file *file = get_struct_file_from_fd(fd_num);

        if (file) {
            fd_arg_task_t fd_arg_task = {
                .pid = p.event->context.task.pid,
                .tid = p.event->context.task.tid,
                .fd = fd_num,
            };

            fd_arg_path_t fd_arg_path = {};
            void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

            bpf_probe_read_str(&fd_arg_path.path, sizeof(fd_arg_path.path), file_path);
            bpf_map_update_elem(&fd_arg_path_map, &fd_arg_task, &fd_arg_path, BPF_ANY);
        }
    }
    if (sys->id != SYSCALL_RT_SIGRETURN && !p.task_info->syscall_traced) {
        save_to_submit_buf(p.event, (void *) &(sys->args.args[0]), sizeof(int), 0);
        events_perf_submit(&p, sys->id, 0);
    }

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
        u32 pid = pid_tgid >> 32;
        task_info = init_task_info(tid, pid, NULL);
        if (unlikely(task_info == NULL)) {
            return 0;
        }
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    long ret = ctx->args[1];

    if (!should_submit(sys->id, p.event))
        goto out;

    // We can't use saved args after execve syscall, as pointers are invalid.
    // To avoid showing execve event both on entry and exit, we only output failed execs.
    if ((sys->id == SYSCALL_EXECVE || sys->id == SYSCALL_EXECVEAT) && (ret == 0))
        goto out;

    save_args_to_submit_buf(p.event, &sys->args);
    p.event->context.ts = sys->ts;
    events_perf_submit(&p, sys->id, ret);

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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(RAW_SYS_ENTER, p.event))
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
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 0);
    events_perf_submit(&p, RAW_SYS_ENTER, 0);
    return 0;
}

// separate hook point for sys_exit event tracing
SEC("raw_tracepoint/trace_sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(RAW_SYS_EXIT, p.event))
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
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 0);
    events_perf_submit(&p, RAW_SYS_EXIT, 0);
    return 0;
}

// PROBES AND HELPERS ------------------------------------------------------------------------------

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;
    p.event->context.ts = sys->ts;

    if (!should_submit(SYSCALL_EXECVE, p.event))
        return 0;

    save_str_to_buf(p.event, (void *) sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[1] /*argv*/, 1);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[2] /*envp*/, 2);
    }

    return events_perf_submit(&p, SYSCALL_EXECVE, 0);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;
    p.event->context.ts = sys->ts;

    if (!should_submit(SYSCALL_EXECVEAT, p.event))
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(p.event, (void *) sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[2] /*argv*/, 2);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[3] /*envp*/, 3);
    }
    save_to_submit_buf(p.event, (void *) &sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_perf_submit(&p, SYSCALL_EXECVEAT, 0);
}

static __always_inline int send_socket_dup(program_data_t *p, u64 oldfd, u64 newfd)
{
    if (!should_submit(SOCKET_DUP, p->event))
        return 0;

    if (!check_fd_type(oldfd, S_IFSOCK)) {
        return 0;
    }

    struct file *f = get_struct_file_from_fd(oldfd);
    if (f == NULL) {
        return -1;
    }

    // this is a socket - submit the SOCKET_DUP event

    save_to_submit_buf(p->event, &oldfd, sizeof(u32), 0);
    save_to_submit_buf(p->event, &newfd, sizeof(u32), 1);

    // get the address
    struct socket *socket_from_file = (struct socket *) READ_KERN(f->private_data);
    if (socket_from_file == NULL) {
        return -1;
    }

    struct sock *sk = get_socket_sock(socket_from_file);
    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in remote;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(p->event, &remote, sizeof(struct sockaddr_in), 2);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 remote;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(p->event, &remote, sizeof(struct sockaddr_in6), 2);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);

        save_to_submit_buf(p->event, &sockaddr, sizeof(struct sockaddr_un), 2);
    }

    return events_perf_submit(p, SOCKET_DUP, 0);
}

SEC("raw_tracepoint/sys_dup")
int sys_dup_exit_tail(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (sys->ret < 0) {
        // dup failed
        return 0;
    }

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

// trace/events/sched.h: TP_PROTO(struct task_struct *parent, struct task_struct *child)
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Note: we don't place should_trace() here, so we can keep track of the cgroups in the system
    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    u64 start_time = get_task_start_time(child);

    task_info_t task = {};
    __builtin_memcpy(&task, p.task_info, sizeof(task_info_t));
    task.recompute_scope = true;
    task.context.tid = get_task_ns_pid(child);
    task.context.host_tid = get_task_host_pid(child);
    task.context.start_time = start_time;
    ret = bpf_map_update_elem(&task_info_map, &task.context.host_tid, &task, BPF_ANY);
    if (ret < 0)
        tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);

    int parent_pid = get_task_host_pid(parent);
    int child_pid = get_task_host_pid(child);

    int parent_tgid = get_task_host_tgid(parent);
    int child_tgid = get_task_host_tgid(child);

    proc_info_t *c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_tgid);
    if (c_proc_info == NULL) {
        // this is a new process (and not just another thread) - add it to proc_info_map

        proc_info_t *p_proc_info = bpf_map_lookup_elem(&proc_info_map, &parent_tgid);
        if (unlikely(p_proc_info == NULL)) {
            // parent proc should exist in proc_map (init_program_data should have set it)
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        bpf_map_update_elem(&proc_info_map, &child_tgid, p_proc_info, BPF_NOEXIST);
        c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_tgid);
        // appease the verifier
        if (unlikely(c_proc_info == NULL)) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        c_proc_info->follow_in_scopes = 0;
        c_proc_info->new_proc = true;
    }

    // update process tree map if the parent has an entry
    if (p.config->proc_tree_filter_enabled_scopes) {
        u32 *tgid_filtered = bpf_map_lookup_elem(&process_tree_map, &parent_tgid);
        if (tgid_filtered) {
            ret = bpf_map_update_elem(&process_tree_map, &child_tgid, tgid_filtered, BPF_ANY);
            if (ret < 0)
                tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);
        }
    }

    if (!should_trace(&p))
        return 0;

    // follow every pid that passed the should_trace() checks (used by the follow filter)
    c_proc_info->follow_in_scopes = p.task_info->matched_scopes;

    if (should_submit(SCHED_PROCESS_FORK, p.event) || p.config->options & OPT_PROCESS_INFO) {
        int parent_ns_pid = get_task_ns_pid(parent);
        int parent_ns_tgid = get_task_ns_tgid(parent);
        int child_ns_pid = get_task_ns_pid(child);
        int child_ns_tgid = get_task_ns_tgid(child);

        save_to_submit_buf(p.event, (void *) &parent_pid, sizeof(int), 0);
        save_to_submit_buf(p.event, (void *) &parent_ns_pid, sizeof(int), 1);
        save_to_submit_buf(p.event, (void *) &parent_tgid, sizeof(int), 2);
        save_to_submit_buf(p.event, (void *) &parent_ns_tgid, sizeof(int), 3);
        save_to_submit_buf(p.event, (void *) &child_pid, sizeof(int), 4);
        save_to_submit_buf(p.event, (void *) &child_ns_pid, sizeof(int), 5);
        save_to_submit_buf(p.event, (void *) &child_tgid, sizeof(int), 6);
        save_to_submit_buf(p.event, (void *) &child_ns_tgid, sizeof(int), 7);
        save_to_submit_buf(p.event, (void *) &start_time, sizeof(u64), 8);

        events_perf_submit(&p, SCHED_PROCESS_FORK, 0);
    }

    return 0;
}

// number of iterations - value that the verifier was seen to cope with - the higher, the better
#define MAX_NUM_MODULES 600

// This map is only used from kernels 5.2 and above.
// If we won't create the map, the userspace will receive an error when interacting with it,
// and since the userspace is not kernel version aware, it won't know whether it's because
// the map simply wasn't created due to kernel version, or something unexpected failed.
BPF_HASH(modules_map, u64, kernel_module_t, MAX_NUM_MODULES);

void __always_inline send_hidden_module(u64 mod_addr, char *mod_name, program_data_t *p)
{
    reset_event_args(p);
    save_to_submit_buf(p->event, &mod_addr, sizeof(u64), 0);
    save_bytes_to_buf(p->event,
                      (void *) mod_name,
                      MODULE_NAME_LEN & MAX_MEM_DUMP_SIZE,
                      1); // this is actually a string, the argument is saved as bytes since the
                          // verifier didn't like it as str

    events_perf_submit(p, HIDDEN_KERNEL_MODULE_SEEKER, 0);
}

// Populate all the modules to an efficient query-able hash map.
// We can't read it once and then hook on do_init_module and free_module since a hidden module will
// remove itself from the list directly and we wouldn't know (hence from our perspective the module
// will reside in the modules list, which could be false). So on every trigger, we go over the
// modules list and populate the map. It gets clean in userspace before every run.
// Since this mechanism is suppose to be triggered every once in a while,
// this should be ok.
static __always_inline bool init_shown_modules()
{
    char modules_sym[8] = "modules";
    struct list_head *head = (struct list_head *) get_symbol_addr(modules_sym);
    bool iterated_all_modules = false;
    struct module *pos, *n;
    kernel_module_t *mod_from_map;

    pos = list_first_entry_ebpf(head, typeof(*pos), list);
    n = pos;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        pos = n;
        n = list_next_entry_ebpf(n, list);

        if (&pos->list == head) {
            iterated_all_modules = true;
            break;
        }
        mod_from_map = bpf_map_lookup_elem(&modules_map, &pos);
        if (mod_from_map == NULL) {
            kernel_module_t m = {.seen_modules_list = true};
            bpf_map_update_elem(&modules_map, &pos, &m, BPF_ANY);
        } else {
            mod_from_map->seen_modules_list = true; // updates the entry in map
        }
    }

    return !iterated_all_modules; // false is valid value
}

static __always_inline bool is_hidden(u64 mod)
{
    kernel_module_t *mod_from_map = bpf_map_lookup_elem(&modules_map, &mod);
    if (mod_from_map == NULL) {
        return true; // if we don't find the module in our map, it means the module is hidden
    } else {
        return !mod_from_map->seen_modules_list; // if it wasn't seen in modules list, it's hidden
    }
}

static __always_inline bool find_modules_from_module_kset_list(program_data_t *p)
{
    char module_kset_sym[12] = "module_kset";
    struct kset *mod_kset = (struct kset *) get_symbol_addr(module_kset_sym);
    struct list_head *head = &(mod_kset->list);
    struct kobject *pos = list_first_entry_ebpf(head, typeof(*pos), entry);
    struct kobject *n = list_next_entry_ebpf(pos, entry);
    bool finished_iterating = false;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        if (READ_KERN(n->name) == NULL) { // Without this the list seems infinite. Also, using pos
                                          // here seems incorrect as it starts from a weird member
            finished_iterating = true;
            break;
        }

        struct module_kobject *mod_kobj =
            (struct module_kobject *) container_of(n, struct module_kobject, kobj);
        if (mod_kobj) {
            struct module *mod = READ_KERN(mod_kobj->mod);
            if (mod) {
                if (is_hidden((u64) mod)) {
                    send_hidden_module((u64) mod, mod->name, p);
                }
            }
        }

        pos = n;
        n = list_next_entry_ebpf(n, entry);
    }

    return !finished_iterating;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || defined(CORE)
BPF_QUEUE(walk_mod_tree_queue, rb_node_t, 2048); // used to walk a rb tree

    #ifdef CORE // in non CORE builds it's already defined
static __always_inline struct latch_tree_node *__lt_from_rb(struct rb_node *node, int idx)
{
    return container_of(node, struct latch_tree_node, node[idx]);
}
    #endif

static __always_inline bool walk_mod_tree(program_data_t *p, struct rb_node *root, int idx)
{
    struct latch_tree_node *ltn;
    struct module *mod;
    bool finished_iterating = false;
    struct rb_node *curr = root;

    #pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        if (curr != NULL) {
            rb_node_t rb_nod = {.node = curr};
            bpf_map_push_elem(&walk_mod_tree_queue, &rb_nod, BPF_EXIST);

            curr = READ_KERN(curr->rb_left); // Move left
        } else {
            rb_node_t rb_nod;
            if (bpf_map_pop_elem(&walk_mod_tree_queue, &rb_nod) != 0) {
                finished_iterating = true;
                break;
            } else {
                curr = rb_nod.node;
                ltn = __lt_from_rb(curr, idx);
                mod = READ_KERN(container_of(ltn, struct mod_tree_node, node)->mod);

                if (is_hidden((u64) mod)) {
                    send_hidden_module((u64) mod, mod->name, p);
                }

                /* We have visited the node and its left subtree.
                Now, it's right subtree's turn */
                curr = READ_KERN(curr->rb_right);
            }
        }
    }

    return !finished_iterating;
}

struct mod_tree_root {
    struct latch_tree_root root;
};

static __always_inline bool find_modules_from_mod_tree(program_data_t *p)
{
    char mod_tree_sym[9] = "mod_tree";
    struct mod_tree_root *m_tree = (struct mod_tree_root *) get_symbol_addr(mod_tree_sym);
    unsigned int seq;
    #ifdef CORE
    if (bpf_core_field_exists(m_tree->root.seq.sequence)) {
        seq = READ_KERN(m_tree->root.seq.sequence); // below 5.10
    } else {
        seq = READ_KERN(m_tree->root.seq.seqcount.sequence); // version >= v5.10
    }
    #else
        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    seq = READ_KERN(m_tree->root.seq.sequence);
        #else
    seq = READ_KERN(m_tree->root.seq.seqcount.sequence);
        #endif
    #endif

    struct rb_node *node = READ_KERN(m_tree->root.tree[seq & 1].rb_node);

    return walk_mod_tree(p, node, seq & 1);
}
#endif

static __always_inline bool check_is_proc_modules_hooked(program_data_t *p)
{
    struct module *pos, *n;
    bool finished_iterating = false;
    char modules_sym[8] = "modules";
    kernel_module_t *mod_from_map;
    struct list_head *head = (struct list_head *) get_symbol_addr(modules_sym);

    pos = list_first_entry_ebpf(head, typeof(*pos), list);
    n = pos;

#pragma unroll
    for (int i = 0; i < MAX_NUM_MODULES; i++) {
        pos = n;
        n = list_next_entry_ebpf(n, list);
        if (&pos->list == head) {
            finished_iterating = true;
            break;
        }

        u64 key = (u64) pos;
        mod_from_map = bpf_map_lookup_elem(&modules_map, &key);
        if ((mod_from_map == NULL) || (mod_from_map != NULL && !mod_from_map->seen_proc_modules)) {
            // Check again with the address being the start of the memory area, since
            // there's a chance the module is in /proc/modules but not in /proc/kallsyms (since the
            // file can be hooked).
            key = (u64) READ_KERN(pos->core_layout.base);
            mod_from_map = bpf_map_lookup_elem(&modules_map, &key);
            // No need to check for seen_proc_modules flag here since if it IS in the map
            // with the address being the start of the memory area, it necessarily got inserted
            // to the map via the /proc/modules userspace logic.
            if (mod_from_map == NULL) {
                // Module was not seen in proc modules, report.
                send_hidden_module((u64) pos, pos->name, p);
            }

            // We couldn't resolve the address from kallsyms but we did see the module in
            // /proc/modules. This probably means that /proc/kallsyms is hooked, but we consider
            // this module not hidden, as tools like lsmod will show it. Thus we gracefully continue
            // and don't report this.
        }
    }

    return !finished_iterating;
}

static __always_inline bool kern_ver_below_min_lkm(struct pt_regs *ctx)
{
// If we're below kernel version 5.2, propogate error to userspace and return
#ifdef CORE
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_sk_storage_get)) {
        goto below_threshold;
    }
#else
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0))
    goto below_threshold;
    #endif
#endif

    return false; // lkm seeker may run!

below_threshold:
    tracee_log(ctx,
               BPF_LOG_LVL_ERROR,
               BPF_LOG_ID_UNSPEC,
               -1); // notify the user that the event logic isn't loaded even though it's requested
    return true;
}

SEC("uprobe/lkm_seeker")
int uprobe_lkm_seeker(struct pt_regs *ctx)
{
    if (kern_ver_below_min_lkm(ctx))
        return 0;

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;
    p.event->context.matched_policies = ULLONG_MAX;

    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;
    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid) {
        return 0;
    }

    if (init_shown_modules() != 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_UNSPEC, 1);
        return 1;
    }

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

    if (check_is_proc_modules_hooked(&p) != 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_UNSPEC, 2);
        return 1;
    }

    bpf_tail_call(ctx, &prog_array, TAIL_HIDDEN_KERNEL_MODULE_KSET);

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

    if (find_modules_from_module_kset_list(&p) != 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_UNSPEC, 3);
        return 1;
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

        // This method is efficient only when the kernel is compiled with
        // CONFIG_MODULES_TREE_LOOKUP=y
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || defined(CORE)
    if (find_modules_from_mod_tree(&p) != 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_UNSPEC, 4);
        return 1;
    }
#endif

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Perform the following checks before should_trace() so we can filter by newly created
    // containers/processes.  We assume that a new container/pod has started when a process of a
    // newly created cgroup and mount ns executed a binary
    if (p.task_info->container_state == CONTAINER_CREATED) {
        u32 mntns = get_task_mnt_ns_id(p.event->task);
        struct task_struct *parent = get_parent_task(p.event->task);
        u32 parent_mntns = get_task_mnt_ns_id(parent);
        if (mntns != parent_mntns) {
            u32 cgroup_id_lsb = p.event->context.task.cgroup_id;
            u8 state = CONTAINER_STARTED;
            bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
            p.task_info->container_state = state;
            p.event->context.task.flags |= CONTAINER_STARTED_FLAG; // Change for current event
            p.task_info->context.flags |= CONTAINER_STARTED_FLAG;  // Change for future task events
        }
    }

    p.task_info->recompute_scope = true;

    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    if (bprm == NULL) {
        return -1;
    }
    struct file *file = get_file_ptr_from_bprm(bprm);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &p.event->context.task.host_pid);
    if (proc_info == NULL) {
        // entry should exist in proc_map (init_program_data should have set it otherwise)
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    proc_info->new_proc = true;

    // extract the binary name to be used in should_trace
    __builtin_memset(proc_info->binary.path, 0, MAX_BIN_PATH_SIZE);
    bpf_probe_read_str(proc_info->binary.path, MAX_BIN_PATH_SIZE, file_path);
    proc_info->binary.mnt_id = p.event->context.task.mnt_id;

    if (!should_trace(&p))
        return 0;

    // Follow this task for matched scopes
    proc_info->follow_in_scopes = p.task_info->matched_scopes;

    if (!should_submit(SCHED_PROCESS_EXEC, p.event) &&
        (p.config->options & OPT_PROCESS_INFO) != OPT_PROCESS_INFO)
        return 0;

    // Note: Starting from kernel 5.9, there are two new interesting fields in bprm that we
    // should consider adding:
    // 1. struct file *executable - can be used to get the executable name passed to an
    // interpreter
    // 2. fdpath                  - generated filename for execveat (after resolving dirfd)
    const char *filename = get_binprm_filename(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);
    umode_t inode_mode = get_inode_mode_from_file(file);

    save_str_to_buf(p.event, (void *) filename, 0);
    save_str_to_buf(p.event, file_path, 1);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);
    save_to_submit_buf(p.event, &inode_mode, sizeof(umode_t), 5);
    // If the interpreter file is the same as the executed one, it means that there is no
    // interpreter. For more information, see the load_elf_phdrs kprobe program.
    if (proc_info->interpreter.inode != 0 &&
        (proc_info->interpreter.device != s_dev || proc_info->interpreter.inode != inode_nr)) {
        save_str_to_buf(p.event, &proc_info->interpreter.pathname, 6);
        save_to_submit_buf(p.event, &proc_info->interpreter.device, sizeof(dev_t), 7);
        save_to_submit_buf(p.event, &proc_info->interpreter.inode, sizeof(unsigned long), 8);
        save_to_submit_buf(p.event, &proc_info->interpreter.ctime, sizeof(u64), 9);
    }

    bpf_tail_call(ctx, &prog_array_tp, TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT);
    return -1;
}

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
    void *stdin_path = get_path_str(GET_FIELD_ADDR(stdin_file->f_path));
    const char *interp = get_binprm_interp(bprm);

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD) {
        invoked_from_kernel = 1;
    }
    save_args_str_arr_to_buf(p.event, (void *) arg_start, (void *) arg_end, argc, 10);
    save_str_to_buf(p.event, (void *) interp, 11);
    save_to_submit_buf(p.event, &stdin_type, sizeof(unsigned short), 12);
    save_str_to_buf(p.event, stdin_path, 13);
    save_to_submit_buf(p.event, &invoked_from_kernel, sizeof(int), 14);
    if (p.config->options & OPT_EXEC_ENV) {
        unsigned long env_start, env_end;
        env_start = get_env_start_from_mm(mm);
        env_end = get_env_end_from_mm(mm);
        int envc = get_envc_from_bprm(bprm);

        save_args_str_arr_to_buf(p.event, (void *) env_start, (void *) env_end, envc, 15);
    }

    events_perf_submit(&p, SCHED_PROCESS_EXEC, 0);
    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // evaluate should_trace before removing this pid from the maps
    bool traced = !!should_trace(&p);

    bpf_map_delete_elem(&task_info_map, &p.event->context.task.host_tid);

    bool group_dead = false;
    struct task_struct *task = p.event->task;
    struct signal_struct *signal = READ_KERN(task->signal);
    atomic_t live = READ_KERN(signal->live);
    // This check could be true for multiple thread exits if the thread count was 0 when the hooks
    // were triggered. This could happen for example if the threads performed exit in different CPUs
    // simultaneously.
    if (live.counter == 0) {
        group_dead = true;
    }

    if (!traced)
        return 0;

    long exit_code = get_task_exit_code(p.event->task);

    if (should_submit(SCHED_PROCESS_EXIT, p.event) || p.config->options & OPT_PROCESS_INFO) {
        save_to_submit_buf(p.event, (void *) &exit_code, sizeof(long), 0);
        save_to_submit_buf(p.event, (void *) &group_dead, sizeof(bool), 1);

        events_perf_submit(&p, SCHED_PROCESS_EXIT, 0);
    }

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
        bpf_map_delete_elem(&process_tree_map, &tgid);
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
    if (!init_program_data(&p, ctx))
        return 0;

    struct socket *old_sock = (struct socket *) saved_args.args[0];
    struct socket *new_sock = (struct socket *) saved_args.args[1];

    if (new_sock == NULL) {
        return -1;
    }
    if (old_sock == NULL) {
        return -1;
    }

    struct sock *sk_new = get_socket_sock(new_sock);
    struct sock *sk_old = get_socket_sock(old_sock);

    u16 family_old = get_sock_family(sk_old);
    u16 family_new = get_sock_family(sk_new);

    if (family_old == AF_INET && family_new == AF_INET) {
        net_conn_v4_t net_details_old = {};
        struct sockaddr_in local;
        get_network_details_from_sock_v4(sk_old, &net_details_old, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details_old, family_old);

        save_to_submit_buf(p.event, (void *) &local, sizeof(struct sockaddr_in), 1);

        net_conn_v4_t net_details_new = {};
        struct sockaddr_in remote;
        get_network_details_from_sock_v4(sk_new, &net_details_new, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details_new, family_new);

        save_to_submit_buf(p.event, (void *) &remote, sizeof(struct sockaddr_in), 2);
    } else if (family_old == AF_INET6 && family_new == AF_INET6) {
        net_conn_v6_t net_details_old = {};
        struct sockaddr_in6 local;
        get_network_details_from_sock_v6(sk_old, &net_details_old, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details_old, family_old);

        save_to_submit_buf(p.event, (void *) &local, sizeof(struct sockaddr_in6), 1);

        net_conn_v6_t net_details_new = {};

        struct sockaddr_in6 remote;
        get_network_details_from_sock_v6(sk_new, &net_details_new, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details_new, family_new);

        save_to_submit_buf(p.event, (void *) &remote, sizeof(struct sockaddr_in6), 2);
    } else if (family_old == AF_UNIX && family_new == AF_UNIX) {
        struct unix_sock *unix_sk_new = (struct unix_sock *) sk_new;
        struct sockaddr_un sockaddr_new = get_unix_sock_addr(unix_sk_new);
        save_to_submit_buf(p.event, (void *) &sockaddr_new, sizeof(struct sockaddr_un), 1);
    } else {
        return 0;
    }
    return events_perf_submit(&p, SOCKET_ACCEPT, 0);
}

// trace/events/sched.h: TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SCHED_SWITCH, p.event))
        return 0;

    struct task_struct *prev = (struct task_struct *) ctx->args[1];
    struct task_struct *next = (struct task_struct *) ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(p.event, (void *) &cpu, sizeof(int), 0);
    save_to_submit_buf(p.event, (void *) &prev_pid, sizeof(int), 1);
    save_str_to_buf(p.event, prev->comm, 2);
    save_to_submit_buf(p.event, (void *) &next_pid, sizeof(int), 3);
    save_str_to_buf(p.event, next->comm, 4);

    return events_perf_submit(&p, SCHED_SWITCH, 0);
}

SEC("kprobe/filldir64")
int BPF_KPROBE(trace_filldir64)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(HIDDEN_INODES, p.event))
        return 0;

    char *process_name = (char *) PT_REGS_PARM2(ctx);
    unsigned long process_inode_number = (unsigned long) PT_REGS_PARM5(ctx);
    if (process_inode_number == 0) {
        save_str_to_buf(p.event, process_name, 0);
        return events_perf_submit(&p, HIDDEN_INODES, 0);
    }
    return 0;
}

SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(trace_call_usermodehelper)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CALL_USERMODE_HELPER, p.event))
        return 0;

    void *path = (void *) PT_REGS_PARM1(ctx);
    unsigned long argv = PT_REGS_PARM2(ctx);
    unsigned long envp = PT_REGS_PARM3(ctx);
    int wait = PT_REGS_PARM4(ctx);

    save_str_to_buf(p.event, path, 0);
    save_str_arr_to_buf(p.event, (const char *const *) argv, 1);
    save_str_arr_to_buf(p.event, (const char *const *) envp, 2);
    save_to_submit_buf(p.event, (void *) &wait, sizeof(int), 3);

    return events_perf_submit(&p, CALL_USERMODE_HELPER, 0);
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DO_EXIT, p.event))
        return 0;

    long code = PT_REGS_PARM1(ctx);

    return events_perf_submit(&p, DO_EXIT, code);
}

// uprobe_syscall_trigger submit to the buff the syscalls function handlers
// address from the syscall table. the syscalls are stored in map which is
// syscalls_to_check_map and the syscall-table address is stored in the
// kernel_symbols map.

SEC("uprobe/trigger_syscall_event")
int uprobe_syscall_trigger(struct pt_regs *ctx)
{
    u64 caller_ctx_id = 0;
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;

    // clang-format off
    //
    // Golang calling convention is being changed from a stack based argument
    // passing (plan9 like) to register based argument passing whenever
    // possible. In arm64, this change happened from go1.17 to go1.18. Use a
    // magic number argument to allow uprobe handler to recognize the calling
    // convention in a simple way.

    #if defined(bpf_target_x86)
        // go1.17, go1.18, go 1.19
        caller_ctx_id = ctx->cx;                                      // 2nd arg
    #elif defined(bpf_target_arm64)
        // go1.17
        u64 magic_num = 0;
        bpf_probe_read(&magic_num, 8, ((void *) ctx->sp) + 16);       // 1st arg
        bpf_probe_read(&caller_ctx_id, 8, ((void *) ctx->sp) + 24);   // 2nd arg
        if (magic_num != UPROBE_MAGIC_NUMBER) {
            // go1.18, go 1.19
            magic_num = ctx->user_regs.regs[1];                       // 1st arg
            caller_ctx_id = ctx->user_regs.regs[2];                   // 2nd arg
        }
    #else
        return 0;
    #endif
    // clang-format on

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;
    p.event->context.matched_policies = ULLONG_MAX;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    int key = 0;
    // TODO: https://github.com/aquasecurity/tracee/issues/2055
    if (bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &key) == NULL)
        return 0;

    char syscall_table_sym[15] = "sys_call_table";
    u64 *syscall_table_addr = (u64 *) get_symbol_addr(syscall_table_sym);
    if (unlikely(syscall_table_addr == 0))
        return 0;
    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    u64 idx;
    unsigned long syscall_addr = 0;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK];

#pragma unroll
    for (int i = 0; i < NUMBER_OF_SYSCALLS_TO_CHECK; i++) {
        idx = i;
        // syscalls_to_check_map format: [syscall#][syscall#][syscall#]
        u64 *syscall_num_p = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &idx);
        if (syscall_num_p == NULL) {
            syscall_address[i] = 0;
            continue;
        }

        syscall_addr = READ_KERN(syscall_table_addr[*syscall_num_p]);
        if (syscall_addr == 0) {
            return 0;
        }

        // skip if in text segment range
        if (syscall_addr >= (u64) stext_addr && syscall_addr < (u64) etext_addr) {
            syscall_address[i] = 0;
            continue;
        }

        syscall_address[i] = syscall_addr;
    }
    save_u64_arr_to_buf(p.event, (const u64 *) syscall_address, NUMBER_OF_SYSCALLS_TO_CHECK, 0);
    save_to_submit_buf(p.event, (void *) &caller_ctx_id, sizeof(uint64_t), 1);
    return events_perf_submit(&p, PRINT_SYSCALL_TABLE, 0);
}

SEC("uprobe/trigger_seq_ops_event")
int uprobe_seq_ops_trigger(struct pt_regs *ctx)
{
    u64 caller_ctx_id = 0;
    u64 *address_array = NULL;
    u64 struct_address;
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;

    // clang-format off
    //
    // Golang calling convention is being changed from a stack based argument
    // passing (plan9 like) to register based argument passing whenever
    // possible. In arm64, this change happened from go1.17 to go1.18. Use a
    // magic number argument to allow uprobe handler to recognize the calling
    // convention in a simple way.

    #if defined(bpf_target_x86)
        // go1.17, go1.18, go 1.19
        caller_ctx_id = ctx->cx;                                      // 2nd arg
        address_array = ((void *) ctx->sp + 8);                       // 3rd arg
    #elif defined(bpf_target_arm64)
        // go1.17
        u64 magic_num = 0;
        bpf_probe_read(&magic_num, 8, ((void *) ctx->sp) + 16);       // 1st arg
        bpf_probe_read(&caller_ctx_id, 8, ((void *) ctx->sp) + 24);   // 2nd arg
        address_array = ((void *) ctx->sp + 32);                      // 3rd arg
        if (magic_num != UPROBE_MAGIC_NUMBER) {
            // go1.18 and go1.19
            magic_num = ctx->user_regs.regs[1];                       // 1st arg
            caller_ctx_id = ctx->user_regs.regs[2];                   // 2nd arg
            address_array = ((void *) ctx->sp + 8);                   // 3rd arg
        }
    #else
        return 0;
    #endif
    // clang-format on

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;
    p.event->context.matched_policies = ULLONG_MAX;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    u32 count_off = p.event->buf_off + 1;
    save_u64_arr_to_buf(p.event, NULL, 0, 0); // init u64 array with size 0

#pragma unroll
    for (int i = 0; i < NET_SEQ_OPS_TYPES; i++) {
        bpf_probe_read(&struct_address, 8, (address_array + i));
        struct seq_operations *seq_ops = (struct seq_operations *) struct_address;

        u64 show_addr = (u64) READ_KERN(seq_ops->show);
        if (show_addr == 0)
            return 0;
        if (show_addr >= (u64) stext_addr && show_addr < (u64) etext_addr)
            show_addr = 0;

        u64 start_addr = (u64) READ_KERN(seq_ops->start);
        if (start_addr == 0)
            return 0;
        if (start_addr >= (u64) stext_addr && start_addr < (u64) etext_addr)
            start_addr = 0;

        u64 next_addr = (u64) READ_KERN(seq_ops->next);
        if (next_addr == 0)
            return 0;
        if (next_addr >= (u64) stext_addr && next_addr < (u64) etext_addr)
            next_addr = 0;

        u64 stop_addr = (u64) READ_KERN(seq_ops->stop);
        if (stop_addr == 0)
            return 0;
        if (stop_addr >= (u64) stext_addr && stop_addr < (u64) etext_addr)
            stop_addr = 0;

        u64 seq_ops_addresses[NET_SEQ_OPS_SIZE + 1] = {show_addr, start_addr, next_addr, stop_addr};

        add_u64_elements_to_buf(p.event, (const u64 *) seq_ops_addresses, 4, count_off);
    }

    save_to_submit_buf(p.event, (void *) &caller_ctx_id, sizeof(uint64_t), 1);
    events_perf_submit(&p, PRINT_NET_SEQ_OPS, 0);
    return 0;
}

SEC("uprobe/trigger_mem_dump_event")
int uprobe_mem_dump_trigger(struct pt_regs *ctx)
{
    u64 address = 0;
    u64 size = 0;
    u64 caller_ctx_id = 0;
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;

#if defined(bpf_target_x86)
    address = ctx->bx;       // 1st arg
    size = ctx->cx;          // 2nd arg
    caller_ctx_id = ctx->di; // 3rd arg
#elif defined(bpf_target_arm64)
    address = ctx->user_regs.regs[1];       // 1st arg
    size = ctx->user_regs.regs[2];          // 2nd arg
    caller_ctx_id = ctx->user_regs.regs[3]; // 3rd arg
#else
    return 0;
#endif

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Uprobes are not triggered by syscalls, so we need to override the false value.
    p.event->context.syscall = NO_SYSCALL;
    p.event->context.matched_policies = ULLONG_MAX;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    if (size <= 0)
        return 0;

    int ret = save_bytes_to_buf(p.event, (void *) address, size & MAX_MEM_DUMP_SIZE, 0);
    // return in case of failed pointer read
    if (ret == 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_MEM_READ, ret);
        return 0;
    }
    save_to_submit_buf(p.event, (void *) &address, sizeof(void *), 1);
    save_to_submit_buf(p.event, &size, sizeof(u64), 2);
    save_to_submit_buf(p.event, &caller_ctx_id, sizeof(u64), 3);

    return events_perf_submit(&p, PRINT_MEM_DUMP, 0);
}

static __always_inline struct trace_kprobe *get_trace_kprobe_from_trace_probe(void *tracep)
{
    struct trace_kprobe *tracekp =
        (struct trace_kprobe *) container_of(tracep, struct trace_kprobe, tp);

    return tracekp;
}

static __always_inline struct trace_uprobe *get_trace_uprobe_from_trace_probe(void *tracep)
{
    struct trace_uprobe *traceup =
        (struct trace_uprobe *) container_of(tracep, struct trace_uprobe, tp);

    return traceup;
}

// This function returns a pointer to struct trace_probe from struct trace_event_call.
static __always_inline void *get_trace_probe_from_trace_event_call(struct trace_event_call *call)
{
    void *tracep_ptr;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0))
    tracep_ptr = container_of(call, struct trace_probe, call);
    #else
    struct trace_probe_event *tpe = container_of(call, struct trace_probe_event, call);
    struct list_head probes = READ_KERN(tpe->probes);
    tracep_ptr = container_of(probes.next, struct trace_probe, list);
    #endif
#else
    struct trace_probe___v53 *legacy_tracep;
    if (bpf_core_field_exists(legacy_tracep->call)) {
        tracep_ptr = container_of(call, struct trace_probe___v53, call);
    } else {
        struct trace_probe_event *tpe = container_of(call, struct trace_probe_event, call);
        struct list_head probes = READ_KERN(tpe->probes);
        tracep_ptr = container_of(probes.next, struct trace_probe, list);
    }
#endif

    return tracep_ptr;
}

enum perf_type_e
{
    PERF_TRACEPOINT,
    PERF_KPROBE,
    PERF_KRETPROBE,
    PERF_UPROBE,
    PERF_URETPROBE
};

// Inspired by bpf_get_perf_event_info() kernel func.
// https://elixir.bootlin.com/linux/v5.19.2/source/kernel/trace/bpf_trace.c#L2123
static __always_inline int
send_bpf_attach(program_data_t *p, struct file *bpf_prog_file, struct file *perf_event_file)
{
    if (!should_submit(BPF_ATTACH, p->event)) {
        return 0;
    }

// get real values of TRACE_EVENT_FL_KPROBE and TRACE_EVENT_FL_UPROBE.
// these values were changed in kernels >= 5.15.
#ifdef CORE
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
#endif

    // get perf event details

// clang-format off
#define MAX_PERF_EVENT_NAME ((MAX_PATH_PREF_SIZE > MAX_KSYM_NAME_SIZE) ? \
    MAX_PATH_PREF_SIZE : MAX_KSYM_NAME_SIZE)
// clang-format on
#define REQUIRED_SYSTEM_LENGTH 9

    struct perf_event *event = (struct perf_event *) READ_KERN(perf_event_file->private_data);
    struct trace_event_call *tp_event = READ_KERN(event->tp_event);
    char event_name[MAX_PERF_EVENT_NAME];
    u64 probe_addr = 0;
    int perf_type;

    int flags = READ_KERN(tp_event->flags);

    // check if syscall_tracepoint
    bool is_syscall_tracepoint = false;
    struct trace_event_class *tp_class = READ_KERN(tp_event->class);
    char class_system[REQUIRED_SYSTEM_LENGTH];
    bpf_probe_read_str(&class_system, REQUIRED_SYSTEM_LENGTH, READ_KERN(tp_class->system));
    class_system[REQUIRED_SYSTEM_LENGTH - 1] = '\0';
    if (has_prefix("syscalls", class_system, REQUIRED_SYSTEM_LENGTH)) {
        is_syscall_tracepoint = true;
    }

    if (flags & TRACE_EVENT_FL_TRACEPOINT) { // event is tracepoint

        perf_type = PERF_TRACEPOINT;
        struct tracepoint *tp = READ_KERN(tp_event->tp);
        bpf_probe_read_str(&event_name, MAX_KSYM_NAME_SIZE, READ_KERN(tp->name));

    } else if (is_syscall_tracepoint) { // event is syscall tracepoint

        perf_type = PERF_TRACEPOINT;
        bpf_probe_read_str(&event_name, MAX_KSYM_NAME_SIZE, READ_KERN(tp_event->name));

    } else {
        bool is_ret_probe = false;
        void *tracep_ptr = get_trace_probe_from_trace_event_call(tp_event);

        if (flags & TRACE_EVENT_FL_KPROBE) { // event is kprobe

            struct trace_kprobe *tracekp = get_trace_kprobe_from_trace_probe(tracep_ptr);

            // check if probe is a kretprobe
            struct kretprobe *krp = &tracekp->rp;
            kretprobe_handler_t handler_f = READ_KERN(krp->handler);
            if (handler_f != NULL)
                is_ret_probe = true;

            if (is_ret_probe)
                perf_type = PERF_KRETPROBE;
            else
                perf_type = PERF_KPROBE;

            // get symbol name
            bpf_probe_read_str(&event_name, MAX_KSYM_NAME_SIZE, READ_KERN(tracekp->symbol));

            // get symbol address
            if (!event_name[0])
                probe_addr = (unsigned long) READ_KERN(krp->kp.addr);

        } else if (flags & TRACE_EVENT_FL_UPROBE) { // event is uprobe

            struct trace_uprobe *traceup = get_trace_uprobe_from_trace_probe(tracep_ptr);

            // determine if ret probe
            struct uprobe_consumer *upc = &traceup->consumer;
            void *handler_f = READ_KERN(upc->ret_handler);
            if (handler_f != NULL)
                is_ret_probe = true;

            if (is_ret_probe)
                perf_type = PERF_URETPROBE;
            else
                perf_type = PERF_UPROBE;

            // get binary path
            bpf_probe_read_str(&event_name, MAX_PATH_PREF_SIZE, READ_KERN(traceup->filename));

            // get symbol offset
            probe_addr = READ_KERN(traceup->offset);

        } else {
            // unsupported perf type
            return 0;
        }
    }

    // get bpf prog details

    struct bpf_prog *prog = (struct bpf_prog *) READ_KERN(bpf_prog_file->private_data);
    int prog_type = READ_KERN(prog->type);
    struct bpf_prog_aux *prog_aux = READ_KERN(prog->aux);
    u32 prog_id = READ_KERN(prog_aux->id);
    char prog_name[BPF_OBJ_NAME_LEN];
    bpf_probe_read_str(&prog_name, BPF_OBJ_NAME_LEN, prog_aux->name);

    // get usage of helpers
    bpf_used_helpers_t *val = bpf_map_lookup_elem(&bpf_attach_map, &prog_id);
    if (val == NULL)
        return 0;

    // submit the event

    save_to_submit_buf(p->event, &prog_type, sizeof(int), 0);
    save_str_to_buf(p->event, (void *) &prog_name, 1);
    save_to_submit_buf(p->event, &prog_id, sizeof(u32), 2);
    save_u64_arr_to_buf(p->event, (const u64 *) val->helpers, 4, 3);
    save_str_to_buf(p->event, (void *) &event_name, 4);
    save_to_submit_buf(p->event, &probe_addr, sizeof(u64), 5);
    save_to_submit_buf(p->event, &perf_type, sizeof(int), 6);

    events_perf_submit(p, BPF_ATTACH, 0);

    // delete from map
    bpf_map_delete_elem(&bpf_attach_map, &prog_id);

    return 0;
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(trace_security_file_ioctl)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    unsigned int cmd = PT_REGS_PARM2(ctx);

    if (cmd == PERF_EVENT_IOC_SET_BPF) {
        struct file *perf_event_file = (struct file *) PT_REGS_PARM1(ctx);
        unsigned long fd = PT_REGS_PARM3(ctx);
        struct file *bpf_prog_file = get_struct_file_from_fd(fd);

        send_bpf_attach(&p, bpf_prog_file, perf_event_file);
    }

    return 0;
}

// trace/events/cgroup.h:
// TP_PROTO(struct cgroup *dst_cgrp, const char *path, struct task_struct *task, bool threadgroup)
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CGROUP_ATTACH_TASK, p.event))
        return 0;

    char *path = (char *) ctx->args[1];
    struct task_struct *task = (struct task_struct *) ctx->args[2];

    int pid = get_task_host_pid(task);
    char *comm = READ_KERN(task->comm);

    save_str_to_buf(p.event, path, 0);
    save_str_to_buf(p.event, comm, 1);
    save_to_submit_buf(p.event, (void *) &pid, sizeof(int), 2);
    events_perf_submit(&p, CGROUP_ATTACH_TASK, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    p.event->context.matched_policies = ULLONG_MAX; // see tracee.GetEssentialEvents

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((p.config->options & OPT_CGROUP_V1) && (p.config->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update) {
        // Assume this is a new container. If not, userspace code will delete this entry
        u8 state = CONTAINER_CREATED;
        bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
        p.task_info->container_state = state;
    }

    save_to_submit_buf(p.event, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(p.event, path, 1);
    save_to_submit_buf(p.event, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&p, CGROUP_MKDIR, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    p.event->context.matched_policies = ULLONG_MAX; // see tracee.GetEssentialEvents

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((p.config->options & OPT_CGROUP_V1) && (p.config->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update)
        bpf_map_delete_elem(&containers_map, &cgroup_id_lsb);

    save_to_submit_buf(p.event, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(p.event, path, 1);
    save_to_submit_buf(p.event, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&p, CGROUP_RMDIR, 0);

    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_BPRM_CHECK, p.event))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    struct file *file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 2);

    return events_perf_submit(&p, SECURITY_BPRM_CHECK, 0);
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_FILE_OPEN, p.event))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    // Load the arguments given to the open syscall (which eventually invokes this function)
    char empty_string[1] = "";
    void *syscall_pathname = &empty_string;
    syscall_data_t *sys = NULL;
    bool syscall_traced = p.task_info->syscall_traced;
    if (syscall_traced) {
        sys = &p.task_info->syscall_data;
        switch (sys->id) {
            case SYSCALL_OPEN:
                syscall_pathname = (void *) sys->args.args[0];
                break;
            case SYSCALL_OPENAT:
            case SYSCALL_OPENAT2:
                syscall_pathname = (void *) sys->args.args[1];
                break;
        }
    }

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, (void *) GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);
    save_str_to_buf(p.event, syscall_pathname, 5);

    return events_perf_submit(&p, SECURITY_FILE_OPEN, 0);
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_security_sb_mount)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SB_MOUNT, p.event))
        return 0;

    const char *dev_name = (const char *) PT_REGS_PARM1(ctx);
    struct path *path = (struct path *) PT_REGS_PARM2(ctx);
    const char *type = (const char *) PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long) PT_REGS_PARM4(ctx);

    void *path_str = get_path_str(path);

    save_str_to_buf(p.event, (void *) dev_name, 0);
    save_str_to_buf(p.event, path_str, 1);
    save_str_to_buf(p.event, (void *) type, 2);
    save_to_submit_buf(p.event, &flags, sizeof(unsigned long), 3);

    return events_perf_submit(&p, SECURITY_SB_MOUNT, 0);
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_UNLINK, p.event))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);
    u64 ctime = get_ctime_nanosec_from_dentry(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 3);

    return events_perf_submit(&p, SECURITY_INODE_UNLINK, 0);
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(COMMIT_CREDS, p.event))
        return 0;

    struct cred *new = (struct cred *) PT_REGS_PARM1(ctx);
    struct cred *old = (struct cred *) get_task_real_cred(p.event->task);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    struct user_namespace *userns_old = READ_KERN(old->user_ns);
    struct user_namespace *userns_new = READ_KERN(new->user_ns);

    old_slim.uid = READ_KERN(old->uid.val);
    old_slim.gid = READ_KERN(old->gid.val);
    old_slim.suid = READ_KERN(old->suid.val);
    old_slim.sgid = READ_KERN(old->sgid.val);
    old_slim.euid = READ_KERN(old->euid.val);
    old_slim.egid = READ_KERN(old->egid.val);
    old_slim.fsuid = READ_KERN(old->fsuid.val);
    old_slim.fsgid = READ_KERN(old->fsgid.val);
    old_slim.user_ns = READ_KERN(userns_old->ns.inum);
    old_slim.securebits = READ_KERN(old->securebits);

    new_slim.uid = READ_KERN(new->uid.val);
    new_slim.gid = READ_KERN(new->gid.val);
    new_slim.suid = READ_KERN(new->suid.val);
    new_slim.sgid = READ_KERN(new->sgid.val);
    new_slim.euid = READ_KERN(new->euid.val);
    new_slim.egid = READ_KERN(new->egid.val);
    new_slim.fsuid = READ_KERN(new->fsuid.val);
    new_slim.fsgid = READ_KERN(new->fsgid.val);
    new_slim.user_ns = READ_KERN(userns_new->ns.inum);
    new_slim.securebits = READ_KERN(new->securebits);

    // Currently, (2021), there are ~40 capabilities in the Linux kernel which are stored in an u32
    // array of length 2. This might change in the (not so near) future as more capabilities will be
    // added. For now, we use u64 to store this array in one piece

    kernel_cap_t caps;
    caps = READ_KERN(old->cap_inheritable);
    old_slim.cap_inheritable = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_permitted);
    old_slim.cap_permitted = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_effective);
    old_slim.cap_effective = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_bset);
    old_slim.cap_bset = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_ambient);
    old_slim.cap_ambient = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];

    caps = READ_KERN(new->cap_inheritable);
    new_slim.cap_inheritable = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_permitted);
    new_slim.cap_permitted = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_effective);
    new_slim.cap_effective = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_bset);
    new_slim.cap_bset = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_ambient);
    new_slim.cap_ambient = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];

    save_to_submit_buf(p.event, (void *) &old_slim, sizeof(slim_cred_t), 0);
    save_to_submit_buf(p.event, (void *) &new_slim, sizeof(slim_cred_t), 1);

    if ((old_slim.uid != new_slim.uid) || (old_slim.gid != new_slim.gid) ||
        (old_slim.suid != new_slim.suid) || (old_slim.sgid != new_slim.sgid) ||
        (old_slim.euid != new_slim.euid) || (old_slim.egid != new_slim.egid) ||
        (old_slim.fsuid != new_slim.fsuid) || (old_slim.fsgid != new_slim.fsgid) ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable) ||
        (old_slim.cap_permitted != new_slim.cap_permitted) ||
        (old_slim.cap_effective != new_slim.cap_effective) ||
        (old_slim.cap_bset != new_slim.cap_bset) ||
        (old_slim.cap_ambient != new_slim.cap_ambient)) {
        events_perf_submit(&p, COMMIT_CREDS, 0);
    }

    return 0;
}

SEC("kprobe/switch_task_namespaces")
int BPF_KPROBE(trace_switch_task_namespaces)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SWITCH_TASK_NS, p.event))
        return 0;

    struct task_struct *task = (struct task_struct *) PT_REGS_PARM1(ctx);
    struct nsproxy *new = (struct nsproxy *) PT_REGS_PARM2(ctx);

    if (!new)
        return 0;

    pid_t pid = READ_KERN(task->pid);
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

    save_to_submit_buf(p.event, (void *) &pid, sizeof(int), 0);

    if (old_mnt != new_mnt)
        save_to_submit_buf(p.event, (void *) &new_mnt, sizeof(u32), 1);
    if (old_pid != new_pid)
        save_to_submit_buf(p.event, (void *) &new_pid, sizeof(u32), 2);
    if (old_uts != new_uts)
        save_to_submit_buf(p.event, (void *) &new_uts, sizeof(u32), 3);
    if (old_ipc != new_ipc)
        save_to_submit_buf(p.event, (void *) &new_ipc, sizeof(u32), 4);
    if (old_net != new_net)
        save_to_submit_buf(p.event, (void *) &new_net, sizeof(u32), 5);
    if (old_cgroup != new_cgroup)
        save_to_submit_buf(p.event, (void *) &new_cgroup, sizeof(u32), 6);
    if (p.event->context.argnum > 1)
        events_perf_submit(&p, SWITCH_TASK_NS, 0);

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CAP_CAPABLE, p.event))
        return 0;

    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(p.event, (void *) &cap, sizeof(int), 0);

    return events_perf_submit(&p, CAP_CAPABLE, 0);
}

SEC("kprobe/security_socket_create")
int BPF_KPROBE(trace_security_socket_create)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_CREATE, p.event))
        return 0;

    int family = (int) PT_REGS_PARM1(ctx);
    int type = (int) PT_REGS_PARM2(ctx);
    int protocol = (int) PT_REGS_PARM3(ctx);
    int kern = (int) PT_REGS_PARM4(ctx);

    save_to_submit_buf(p.event, (void *) &family, sizeof(int), 0);
    save_to_submit_buf(p.event, (void *) &type, sizeof(int), 1);
    save_to_submit_buf(p.event, (void *) &protocol, sizeof(int), 2);
    save_to_submit_buf(p.event, (void *) &kern, sizeof(int), 3);

    return events_perf_submit(&p, SECURITY_SOCKET_CREATE, 0);
}

SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(trace_security_inode_symlink)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_SYMLINK, p.event))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    const char *old_name = (const char *) PT_REGS_PARM3(ctx);

    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_str_to_buf(p.event, (void *) old_name, 1);

    return events_perf_submit(&p, SECURITY_INODE_SYMLINK, 0);
}

SEC("kprobe/proc_create")
int BPF_KPROBE(trace_proc_create)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(PROC_CREATE, p.event))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM4(ctx);

    save_str_to_buf(p.event, name, 0);
    save_to_submit_buf(p.event, (void *) &proc_ops_addr, sizeof(u64), 1);

    return events_perf_submit(&p, PROC_CREATE, 0);
}

SEC("kprobe/debugfs_create_file")
int BPF_KPROBE(trace_debugfs_create_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(DEBUGFS_CREATE_FILE, p.event))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    mode_t mode = (unsigned short) PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM3(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM5(ctx);

    save_str_to_buf(p.event, name, 0);
    save_str_to_buf(p.event, dentry_path, 1);
    save_to_submit_buf(p.event, &mode, sizeof(mode_t), 2);
    save_to_submit_buf(p.event, (void *) &proc_ops_addr, sizeof(u64), 3);

    return events_perf_submit(&p, DEBUGFS_CREATE_FILE, 0);
}

SEC("kprobe/debugfs_create_dir")
int BPF_KPROBE(trace_debugfs_create_dir)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(DEBUGFS_CREATE_DIR, p.event))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(p.event, name, 0);
    save_str_to_buf(p.event, dentry_path, 1);

    return events_perf_submit(&p, DEBUGFS_CREATE_DIR, 0);
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_LISTEN, p.event))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int backlog = (int) PT_REGS_PARM2(ctx);

    // Load the arguments given to the listen syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_LISTEN)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);
    save_sockaddr_to_buf(p.event, sock, 1);
    save_to_submit_buf(p.event, (void *) &backlog, sizeof(int), 2);

    return events_perf_submit(&p, SECURITY_SOCKET_LISTEN, 0);
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_CONNECT, p.event))
        return 0;

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
#if defined(__TARGET_ARCH_x86) // TODO: issue: #1129
    uint addr_len = (uint) PT_REGS_PARM3(ctx);
#endif

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the connect syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_CONNECT)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);

    if (sa_fam == AF_INET) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in), 1);
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in6), 1);
    } else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *) address);
            save_to_submit_buf(p.event, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&p, SECURITY_SOCKET_CONNECT, 0);
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);

    struct socket *new_sock = (struct socket *) PT_REGS_PARM2(ctx);

    // save sockets for "socket_accept event"
    if (should_submit(SOCKET_ACCEPT, p.event)) {
        args_t args = {};
        args.args[0] = (unsigned long) sock;
        args.args[1] = (unsigned long) new_sock;
        save_args(&args, SOCKET_ACCEPT);
    }

    if (!should_submit(SECURITY_SOCKET_ACCEPT, p.event))
        return 0;

    // Load the arguments given to the accept syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || (sys->id != SYSCALL_ACCEPT && sys->id != SYSCALL_ACCEPT4))
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);
    save_sockaddr_to_buf(p.event, sock, 1);

    return events_perf_submit(&p, SECURITY_SOCKET_ACCEPT, 0);
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_BIND, p.event))
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

    // Load the arguments given to the bind syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_BIND)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);

    u16 protocol = get_sock_protocol(sk);
    net_id_t connect_id = {0};
    connect_id.protocol = protocol;

    if (sa_fam == AF_INET) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in), 1);

        struct sockaddr_in *addr = (struct sockaddr_in *) address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin_port)) {
            connect_id.address.s6_addr32[3] = READ_KERN(addr->sin_addr).s_addr;
            connect_id.address.s6_addr16[5] = 0xffff;
            connect_id.port = READ_KERN(addr->sin_port);
        }
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in6), 1);

        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin6_port)) {
            connect_id.address = READ_KERN(addr->sin6_addr);
            connect_id.port = READ_KERN(addr->sin6_port);
        }
    } else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *) address);
            save_to_submit_buf(p.event, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&p, SECURITY_SOCKET_BIND, 0);
}

SEC("kprobe/security_socket_setsockopt")
int BPF_KPROBE(trace_security_socket_setsockopt)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_SETSOCKOPT, p.event))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int level = (int) PT_REGS_PARM2(ctx);
    int optname = (int) PT_REGS_PARM3(ctx);

    // Load the arguments given to the setsockopt syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (sys == NULL) {
        return -1;
    }

    if (!p.task_info->syscall_traced || sys->id != SYSCALL_SETSOCKOPT)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);
    save_to_submit_buf(p.event, (void *) &level, sizeof(int), 1);
    save_to_submit_buf(p.event, (void *) &optname, sizeof(int), 2);
    save_sockaddr_to_buf(p.event, sock, 3);

    return events_perf_submit(&p, SECURITY_SOCKET_SETSOCKOPT, 0);
}

enum bin_type_e
{
    SEND_VFS_WRITE = 1,
    SEND_MPROTECT,
    SEND_KERNEL_MODULE,
};

static __always_inline u32 tail_call_send_bin(void *ctx,
                                              program_data_t *p,
                                              bin_args_t *bin_args,
                                              int tail_call)
{
    if (p->event->buf_off < ARGS_BUF_SIZE - sizeof(bin_args_t)) {
        bpf_probe_read(&(p->event->args[p->event->buf_off]), sizeof(bin_args_t), bin_args);
        if (tail_call == TAIL_SEND_BIN)
            bpf_tail_call(ctx, &prog_array, tail_call);
        else if (tail_call == TAIL_SEND_BIN_TP)
            bpf_tail_call(ctx, &prog_array_tp, tail_call);
    }

    return 0;
}

static __always_inline u32 send_bin_helper(void *ctx, void *prog_array, int tail_call)
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
    if (!event || (event->buf_off > ARGS_BUF_SIZE - sizeof(bin_args_t)))
        return 0;

    bin_args_t *bin_args = (bin_args_t *) &(event->args[event->buf_off]);

    if (bin_args->full_size <= 0) {
        // If there are more vector elements, continue to the next one
        bin_args->iov_idx++;
        if (bin_args->iov_idx < bin_args->iov_len) {
            // Handle the rest of write recursively
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

    bpf_probe_read((void **) &(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args->type);

    u64 cgroup_id = event->context.task.cgroup_id;
    bpf_probe_read((void **) &(file_buf_p->buf[F_CGROUP_ID]), sizeof(u64), &cgroup_id);

    // Save metadata to be used in filename
    bpf_probe_read((void **) &(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args->metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read((void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

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
        bpf_probe_read(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);
        bpf_probe_read((void **) &(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, bin_args->ptr);
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
        bpf_probe_read((void **) &(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
        bpf_probe_read((void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
        bpf_probe_read(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

        // Satisfy validator by setting buffer bounds
        int size = (F_CHUNK_OFF + chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
        bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, size);
    }

    // We finished writing an element of the vector - continue to next element
    bin_args->iov_idx++;
    if (bin_args->iov_idx < bin_args->iov_len) {
        // Handle the rest of write recursively
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

static __always_inline int
submit_magic_write(program_data_t *p, file_info_t *file_info, io_data_t io_data, u32 bytes_written)
{
    u32 header_bytes = FILE_MAGIC_HDR_SIZE;
    if (header_bytes > bytes_written)
        header_bytes = bytes_written;

    u8 header[FILE_MAGIC_HDR_SIZE];
    __builtin_memset(&header, 0, sizeof(header));

    save_str_to_buf(p->event, file_info->pathname_p, 0);

    if (io_data.is_buf) {
        if (header_bytes < FILE_MAGIC_HDR_SIZE)
            bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, io_data.ptr);
        else
            bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, io_data.ptr);
    } else {
        struct iovec io_vec;
        __builtin_memset(&io_vec, 0, sizeof(io_vec));
        bpf_probe_read(&io_vec, sizeof(struct iovec), io_data.ptr);
        if (header_bytes < FILE_MAGIC_HDR_SIZE)
            bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, io_vec.iov_base);
        else
            bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, io_vec.iov_base);
    }

    save_bytes_to_buf(p->event, header, header_bytes, 1);
    save_to_submit_buf(p->event, &file_info->device, sizeof(dev_t), 2);
    save_to_submit_buf(p->event, &file_info->inode, sizeof(unsigned long), 3);

    // Submit magic_write event
    return events_perf_submit(p, MAGIC_WRITE, bytes_written);
}

static __always_inline bool should_submit_io_event(u32 event_id, program_data_t *p)
{
    return ((event_id == VFS_READ || event_id == VFS_READV || event_id == VFS_WRITE ||
             event_id == VFS_WRITEV || event_id == __KERNEL_WRITE) &&
            should_submit(event_id, p->event));
}

/** do_file_io_operation - generic file IO (read and write) event creator.
 *
 * @ctx:            the state of the registers prior the hook.
 * @event_id:       the ID of the event to be created.
 * @tail_call_id:   the ID of the tail call to be called before function return.
 * @is_read:        true if the operation is read. False if write.
 * @is_buf:         true if the non-file side of the operation is a buffer. False if io_vector.
 */
static __always_inline int
do_file_io_operation(struct pt_regs *ctx, u32 event_id, u32 tail_call_id, bool is_read, bool is_buf)
{
    args_t saved_args;
    if (load_args(&saved_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        del_args(event_id);
        return 0;
    }

    bool should_submit_magic_write = should_submit(MAGIC_WRITE, p.event);
    bool should_submit_io = should_submit_io_event(event_id, &p);

    if (!should_submit_io && !should_submit_magic_write) {
        bpf_tail_call(ctx, &prog_array, tail_call_id);
        del_args(event_id);
        return 0;
    }

    loff_t start_pos;
    io_data_t io_data;
    file_info_t file_info;

    struct file *file = (struct file *) saved_args.args[0];
    file_info.pathname_p = get_path_str(GET_FIELD_ADDR(file->f_path));

    io_data.is_buf = is_buf;
    io_data.ptr = (void *) saved_args.args[1];
    io_data.len = (unsigned long) saved_args.args[2];
    loff_t *pos = (loff_t *) saved_args.args[3];

    // Extract device id, inode number, and pos (offset)
    file_info.device = get_dev_from_file(file);
    file_info.inode = get_inode_nr_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    bool char_dev = (start_pos == 0);
    u32 io_bytes_amount = PT_REGS_RC(ctx);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= io_bytes_amount;

    if (should_submit_io) {
        save_str_to_buf(p.event, file_info.pathname_p, 0);
        save_to_submit_buf(p.event, &file_info.device, sizeof(dev_t), 1);
        save_to_submit_buf(p.event, &file_info.inode, sizeof(unsigned long), 2);
        save_to_submit_buf(p.event, &io_data.len, sizeof(unsigned long), 3);
        save_to_submit_buf(p.event, &start_pos, sizeof(off_t), 4);

        // Submit io event
        events_perf_submit(&p, event_id, PT_REGS_RC(ctx));
    }

    // magic_write event checks if the header of some file is changed
    if (!is_read && should_submit_magic_write && !char_dev && (start_pos == 0)) {
        reset_event_args(&p);
        submit_magic_write(&p, &file_info, io_data, io_bytes_amount);
    }

    bpf_tail_call(ctx, &prog_array, tail_call_id);
    del_args(event_id);
    return 0;
}

// Capture file write
// Will only capture if:
// 1. File write capture was configured
// 2. File matches the filters given
static __always_inline int capture_file_write(struct pt_regs *ctx, u32 event_id)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        del_args(event_id);
        return 0;
    }

    if ((p.config->options & OPT_CAPTURE_FILES) == 0) {
        del_args(event_id);
        return 0;
    }

    args_t saved_args;
    bin_args_t bin_args = {};
    loff_t start_pos;

    void *ptr;
    struct iovec *vec;
    unsigned long vlen;
    bool has_filter = false;
    bool filter_match = false;

    if (load_args(&saved_args, event_id) != 0)
        return 0;
    del_args(event_id);

    struct file *file = (struct file *) saved_args.args[0];
    if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE) {
        ptr = (void *) saved_args.args[1];
    } else {
        vec = (struct iovec *) saved_args.args[1];
        vlen = saved_args.args[2];
    }
    loff_t *pos = (loff_t *) saved_args.args[3];

    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    if (p.event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE)
        return -1;
    bpf_probe_read_str(&(p.event->args[p.event->buf_off]), MAX_STRING_SIZE, file_path);

// Check if capture write was requested for this path
#pragma unroll
    for (int i = 0; i < 3; i++) {
        int idx = i;
        path_filter_t *filter_p = bpf_map_lookup_elem(&file_filter, &idx);
        if (filter_p == NULL)
            return -1;

        if (!filter_p->path[0])
            break;

        has_filter = true;

        if (p.event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE)
            break;

        if (has_prefix(
                filter_p->path, (char *) &p.event->args[p.event->buf_off], MAX_PATH_PREF_SIZE)) {
            filter_match = true;
            break;
        }
    }

    if (has_filter && !filter_match) {
        // There is a filter, but no match
        del_args(event_id);
        return 0;
    }
    // No filter was given, or filter match - continue

    // Extract device id, inode number, mode, and pos (offset)
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    unsigned short i_mode = get_inode_mode_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= PT_REGS_RC(ctx);

    u32 pid = p.event->context.task.pid;

    if (p.event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE)
        return -1;

    if (!has_prefix("/dev/null", (char *) &p.event->args[p.event->buf_off], 10))
        pid = 0;

    bin_args.type = SEND_VFS_WRITE;
    bpf_probe_read(bin_args.metadata, 4, &s_dev);
    bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
    bpf_probe_read(&bin_args.metadata[12], 4, &i_mode);
    bpf_probe_read(&bin_args.metadata[16], 4, &pid);
    bin_args.start_off = start_pos;
    if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE) {
        bin_args.ptr = ptr;
        bin_args.full_size = PT_REGS_RC(ctx);
    } else {
        bin_args.vec = vec;
        bin_args.iov_idx = 0;
        bin_args.iov_len = vlen;
        if (vlen > 0) {
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &vec[0]);
            bin_args.ptr = io_vec.iov_base;
            bin_args.full_size = io_vec.iov_len;
        }
    }

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
    return capture_file_write(ctx, VFS_WRITE);
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
    return capture_file_write(ctx, VFS_WRITEV);
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
    return capture_file_write(ctx, __KERNEL_WRITE);
}

SEC("kprobe/vfs_read")
TRACE_ENT_FUNC(vfs_read, VFS_READ);

SEC("kretprobe/vfs_read")
int BPF_KPROBE(trace_ret_vfs_read)
{
    return do_file_io_operation(ctx, VFS_READ, TAIL_VFS_READ, true, true);
}

SEC("kprobe/vfs_readv")
TRACE_ENT_FUNC(vfs_readv, VFS_READV);

SEC("kretprobe/vfs_readv")
int BPF_KPROBE(trace_ret_vfs_readv)
{
    return do_file_io_operation(ctx, VFS_READV, TAIL_VFS_READV, true, false);
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
            save_to_submit_buf(event, &file_info.device, sizeof(dev_t), 6);                        \
            save_to_submit_buf(event, &file_info.inode, sizeof(unsigned long), 7);                 \
            save_to_submit_buf(event, &file_info.ctime, sizeof(u64), 8);                           \
        }                                                                                          \
        events_perf_submit(&p, MEM_PROT_ALERT, 0);                                                 \
    }

SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_alert)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    // Load the arguments given to the mmap syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_MMAP)
        return 0;

    int prot = sys->args.args[2];

    if ((prot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC) &&
        should_submit(MEM_PROT_ALERT, p.event)) {
        u32 alert = ALERT_MMAP_W_X;
        int fd = sys->args.args[5];
        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];
        struct file *file = get_struct_file_from_fd(fd);
        int prev_prot = 0;
        file_info_t file_info = get_file_info(file);
        submit_mem_prot_alert_event(p.event, alert, addr, len, prot, prev_prot, file_info);
    }

    return 0;
}

SEC("kprobe/do_mmap")
TRACE_ENT_FUNC(do_mmap, DO_MMAP)

SEC("kretprobe/do_mmap")
int BPF_KPROBE(trace_ret_do_mmap)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_submit(DO_MMAP, p.event))
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, DO_MMAP) != 0) {
        // missed entry or not traced
        return 0;
    }

    dev_t s_dev;
    unsigned long inode_nr;
    void *file_path;
    u64 ctime;
    unsigned int flags;

    struct file *file = (struct file *) saved_args.args[0];
    if (file != NULL) {
        s_dev = get_dev_from_file(file);
        inode_nr = get_inode_nr_from_file(file);
        file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
        ctime = get_ctime_nanosec_from_file(file);
    }
    unsigned long len = (unsigned long) saved_args.args[2];
    unsigned long prot = (unsigned long) saved_args.args[3];
    unsigned long mmap_flags = (unsigned long) saved_args.args[4];
    unsigned long pgoff = (unsigned long) saved_args.args[5];
    unsigned long addr = (unsigned long) PT_REGS_RC(ctx);

    save_to_submit_buf(p.event, &addr, sizeof(void *), 0);
    if (file != NULL) {
        save_str_to_buf(p.event, file_path, 1);
        save_to_submit_buf(p.event, &flags, sizeof(unsigned int), 2);
        save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 3);
        save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 4);
        save_to_submit_buf(p.event, &ctime, sizeof(u64), 5);
    }
    save_to_submit_buf(p.event, &pgoff, sizeof(unsigned long), 6);
    save_to_submit_buf(p.event, &len, sizeof(unsigned long), 7);
    save_to_submit_buf(p.event, &prot, sizeof(unsigned long), 8);
    save_to_submit_buf(p.event, &mmap_flags, sizeof(unsigned long), 9);

    return events_perf_submit(&p, DO_MMAP, 0);
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(trace_security_mmap_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    bool submit_sec_mmap_file = should_submit(SECURITY_MMAP_FILE, p.event);
    bool submit_shared_object_loaded = should_submit(SHARED_OBJECT_LOADED, p.event);

    if (!submit_sec_mmap_file && !submit_shared_object_loaded)
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == 0)
        return 0;
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);
    unsigned long prot = (unsigned long) PT_REGS_PARM2(ctx);
    unsigned long mmap_flags = (unsigned long) PT_REGS_PARM3(ctx);

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, (void *) GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);

    if (submit_shared_object_loaded) {
        if ((prot & VM_EXEC) == VM_EXEC && p.event->context.syscall == SYSCALL_MMAP) {
            events_perf_submit(&p, SHARED_OBJECT_LOADED, 0);
        }
    }

    if (submit_sec_mmap_file) {
        save_to_submit_buf(p.event, &prot, sizeof(unsigned long), 5);
        save_to_submit_buf(p.event, &mmap_flags, sizeof(unsigned long), 6);
        return events_perf_submit(&p, SECURITY_MMAP_FILE, 0);
    }

    return 0;
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_security_file_mprotect)
{
    bin_args_t bin_args = {};

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    // Load the arguments given to the mprotect syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced ||
        (sys->id != SYSCALL_MPROTECT && sys->id != SYSCALL_PKEY_MPROTECT))
        return 0;

    int should_submit_mprotect = should_submit(SECURITY_FILE_MPROTECT, p.event);
    int should_submit_mem_prot_alert = should_submit(MEM_PROT_ALERT, p.event);

    if (!should_submit_mprotect && !should_submit_mem_prot_alert) {
        return 0;
    }

    struct vm_area_struct *vma = (struct vm_area_struct *) PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);
    unsigned long prev_prot = get_vma_flags(vma);

    struct file *file = (struct file *) READ_KERN(vma->vm_file);
    file_info_t file_info = get_file_info(file);

    if (should_submit_mprotect) {
        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];

        save_str_to_buf(p.event, file_info.pathname_p, 0);
        save_to_submit_buf(p.event, &reqprot, sizeof(int), 1);
        save_to_submit_buf(p.event, &file_info.ctime, sizeof(u64), 2);
        save_to_submit_buf(p.event, &prev_prot, sizeof(int), 3);
        save_to_submit_buf(p.event, &addr, sizeof(void *), 4);
        save_to_submit_buf(p.event, &len, sizeof(size_t), 5);

        if (sys->id == SYSCALL_PKEY_MPROTECT) {
            int pkey = sys->args.args[3];
            save_to_submit_buf(p.event, &pkey, sizeof(int), 6);
        }

        events_perf_submit(&p, SECURITY_FILE_MPROTECT, 0);
    }

    if (should_submit_mem_prot_alert) {
        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];

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

        if (((prev_prot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)) && (reqprot & VM_EXEC) &&
            !(reqprot & VM_WRITE)) {
            alert = ALERT_MPROT_W_REM;
            should_alert = true;

            if (p.config->options & OPT_EXTRACT_DYN_CODE) {
                should_extract_code = true;
            }
        }
        if (should_alert) {
            reset_event_args(&p);
            submit_mem_prot_alert_event(p.event, alert, addr, len, reqprot, prev_prot, file_info);
        }
        if (should_extract_code) {
            bin_args.type = SEND_MPROTECT;
            bpf_probe_read(bin_args.metadata, sizeof(u64), &p.event->context.ts);
            bin_args.ptr = (char *) addr;
            bin_args.start_off = 0;
            bin_args.full_size = len;

            tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
        }
    }

    return 0;
}

SEC("raw_tracepoint/sys_init_module")
int syscall__init_module(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
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
        bpf_probe_read(bin_args.metadata, 4, &dummy);
        bpf_probe_read(&bin_args.metadata[4], 8, &dummy);
        bpf_probe_read(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read(&bin_args.metadata[16], 8, &len);
        bin_args.ptr = (char *) addr;
        bin_args.start_off = 0;
        bin_args.full_size = (unsigned int) len;

        tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN_TP);
    }
    return 0;
}

// Check (CORE || (!CORE && kernel >= 5.7)) to compile successfully.
// (compiler will try to compile the func even if no execution path leads to it).
#if defined(CORE) || (!defined(CORE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)))
static __always_inline int do_check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd)
{
    if (cmd == BPF_LINK_CREATE) {
        u32 prog_fd = READ_KERN(attr->link_create.prog_fd);
        u32 perf_fd = READ_KERN(attr->link_create.target_fd);

        struct file *bpf_prog_file = get_struct_file_from_fd(prog_fd);
        struct file *perf_event_file = get_struct_file_from_fd(perf_fd);

        send_bpf_attach(p, bpf_prog_file, perf_event_file);
    }

    return 0;
}
#endif

static __always_inline int check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd)
{
// BPF_LINK_CREATE command was only introduced in kernel 5.7.
// nothing to check for kernels < 5.7.
#ifdef CORE
    if (bpf_core_field_exists(attr->link_create)) {
        do_check_bpf_link(p, attr, cmd);
    }
#else
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    do_check_bpf_link(p, attr, cmd);
    #endif
#endif

    return 0;
}

SEC("kprobe/security_bpf")
int BPF_KPROBE(trace_security_bpf)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    int cmd = (int) PT_REGS_PARM1(ctx);

    if (should_submit(SECURITY_BPF, p.event)) {
        // 1st argument == cmd (int)
        save_to_submit_buf(p.event, (void *) &cmd, sizeof(int), 0);
        events_perf_submit(&p, SECURITY_BPF, 0);
    }
    union bpf_attr *attr = (union bpf_attr *) PT_REGS_PARM2(ctx);

    reset_event_args(&p);
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
        long sz = bpf_probe_read_str(prog_name, 16, attr->prog_name);
        if (sz > 0) {
            sz = bpf_probe_read_str(bin_args.metadata, sz, prog_name);
        }

        u32 rand = bpf_get_prandom_u32();
        bpf_probe_read(&bin_args.metadata[16], 4, &rand);
        bpf_probe_read(&bin_args.metadata[20], 4, &pid);
        bpf_probe_read(&bin_args.metadata[24], 4, &insn_size);
        bin_args.ptr = (char *) insns;
        bin_args.start_off = 0;
        bin_args.full_size = insn_size;

        tail_call_send_bin(ctx, &p, &bin_args, TAIL_SEND_BIN);
    }
    return 0;
}

// arm_kprobe can't be hooked in arm64 architecture, use enable logic instead

static __always_inline int arm_kprobe_handler(struct pt_regs *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, KPROBE_ATTACH) != 0) {
        return 0;
    }
    del_args(KPROBE_ATTACH);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct kprobe *kp = (struct kprobe *) saved_args.args[0];
    unsigned int retcode = PT_REGS_RC(ctx);

    if (retcode)
        return 0; // register_kprobe() failed

    char *symbol_name = (char *) READ_KERN(kp->symbol_name);
    u64 pre_handler = (u64) READ_KERN(kp->pre_handler);
    u64 post_handler = (u64) READ_KERN(kp->post_handler);

    save_str_to_buf(p.event, (void *) symbol_name, 0);
    save_to_submit_buf(p.event, (void *) &pre_handler, sizeof(u64), 1);
    save_to_submit_buf(p.event, (void *) &post_handler, sizeof(u64), 2);

    return events_perf_submit(&p, KPROBE_ATTACH, 0);
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_BPF_MAP, p.event))
        return 0;

    struct bpf_map *map = (struct bpf_map *) PT_REGS_PARM1(ctx);

    // 1st argument == map_id (u32)
    save_to_submit_buf(p.event, (void *) GET_FIELD_ADDR(map->id), sizeof(int), 0);
    // 2nd argument == map_name (const char *)
    save_str_to_buf(p.event, (void *) GET_FIELD_ADDR(map->name), 1);

    return events_perf_submit(&p, SECURITY_BPF_MAP, 0);
}

SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(trace_security_bpf_prog)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct bpf_prog *prog = (struct bpf_prog *) PT_REGS_PARM1(ctx);
    struct bpf_prog_aux *prog_aux = READ_KERN(prog->aux);
    u32 prog_id = READ_KERN(prog_aux->id);

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

    if (should_submit(BPF_ATTACH, p.event)) {
        bpf_map_update_elem(&bpf_attach_map, &prog_id, &val, BPF_ANY);
    }

    if (!should_submit(SECURITY_BPF_PROG, p.event)) {
        return 0;
    }

    bool is_load = false;
    void **aux_ptr = bpf_map_lookup_elem(&bpf_prog_load_map, &p.event->context.task.host_tid);
    if (aux_ptr != NULL) {
        if (*aux_ptr == (void *) prog_aux) {
            is_load = true;
        }

        bpf_map_delete_elem(&bpf_prog_load_map, &p.event->context.task.host_tid);
    }

    int prog_type = READ_KERN(prog->type);

    char prog_name[BPF_OBJ_NAME_LEN];
    bpf_probe_read_str(&prog_name, BPF_OBJ_NAME_LEN, prog_aux->name);

    save_to_submit_buf(p.event, &prog_type, sizeof(int), 0);
    save_str_to_buf(p.event, (void *) &prog_name, 1);
    save_u64_arr_to_buf(p.event, (const u64 *) val.helpers, 4, 2);
    save_to_submit_buf(p.event, &prog_id, sizeof(u32), 3);
    save_to_submit_buf(p.event, &is_load, sizeof(bool), 4);

    events_perf_submit(&p, SECURITY_BPF_PROG, 0);

    return 0;
}

SEC("kprobe/bpf_check")
int BPF_KPROBE(trace_bpf_check)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    // this probe is triggered when a bpf program is loaded.
    // we save the aux pointer to be used in security_bpf_prog, to indicate this prog is being
    // loaded - security_bpf_prog is triggered not only on prog load.

    if (!should_submit(SECURITY_BPF_PROG, p.event))
        return 0;

    struct bpf_prog **prog = (struct bpf_prog **) PT_REGS_PARM1(ctx);

    struct bpf_prog *prog_ptr = READ_KERN(*prog);
    struct bpf_prog_aux *prog_aux = READ_KERN(prog_ptr->aux);

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

static __always_inline int handle_bpf_helper_func_id(u32 host_tid, int func_id)
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    int func_id = (int) PT_REGS_PARM3(ctx);

    return handle_bpf_helper_func_id(p.event->context.task.host_tid, func_id);
}

SEC("kprobe/check_helper_call")
int BPF_KPROBE(trace_check_helper_call)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    int func_id;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0))
    func_id = (int) PT_REGS_PARM2(ctx);
#else
    struct bpf_insn *insn = (struct bpf_insn *) PT_REGS_PARM2(ctx);
    func_id = READ_KERN(insn->imm);
#endif

    return handle_bpf_helper_func_id(p.event->context.task.host_tid, func_id);
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_KERNEL_READ_FILE, p.event))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM2(ctx);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 2);
    save_to_submit_buf(p.event, &type_id, sizeof(int), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);

    return events_perf_submit(&p, SECURITY_KERNEL_READ_FILE, 0);
}

SEC("kprobe/security_kernel_post_read_file")
int BPF_KPROBE(trace_security_kernel_post_read_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    char *buf = (char *) PT_REGS_PARM2(ctx);
    loff_t size = (loff_t) PT_REGS_PARM3(ctx);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM4(ctx);

    // Send event if chosen
    if (should_submit(SECURITY_POST_READ_FILE, p.event)) {
        void *file_path = get_path_str(&file->f_path);
        save_str_to_buf(p.event, file_path, 0);
        save_to_submit_buf(p.event, &size, sizeof(loff_t), 1);
        save_to_submit_buf(p.event, &type_id, sizeof(int), 2);
        events_perf_submit(&p, SECURITY_POST_READ_FILE, 0);
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
        bpf_probe_read(bin_args.metadata, 4, &s_dev);
        bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
        bpf_probe_read(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read(&bin_args.metadata[16], 4, &size);
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_MKNOD, p.event))
        return 0;

    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    unsigned short mode = (unsigned short) PT_REGS_PARM3(ctx);
    unsigned int dev = (unsigned int) PT_REGS_PARM4(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_to_submit_buf(p.event, &mode, sizeof(unsigned short), 1);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&p, SECURITY_INODE_MKNOD, 0);
}

SEC("kprobe/device_add")
int BPF_KPROBE(trace_device_add)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DEVICE_ADD, p.event))
        return 0;

    struct device *dev = (struct device *) PT_REGS_PARM1(ctx);
    const char *name = get_device_name(dev);

    struct device *parent_dev = READ_KERN(dev->parent);
    const char *parent_name = get_device_name(parent_dev);

    save_str_to_buf(p.event, (void *) name, 0);
    save_str_to_buf(p.event, (void *) parent_name, 1);

    return events_perf_submit(&p, DEVICE_ADD, 0);
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(REGISTER_CHRDEV, p.event))
        return 0;

    unsigned int major_number = (unsigned int) saved_args.args[0];
    unsigned int returned_major = PT_REGS_RC(ctx);

    // sets the returned major to the requested one in case of a successful registration
    if (major_number > 0 && returned_major == 0) {
        returned_major = major_number;
    }

    char *char_device_name = (char *) saved_args.args[3];
    struct file_operations *char_device_fops = (struct file_operations *) saved_args.args[4];

    save_to_submit_buf(p.event, &major_number, sizeof(unsigned int), 0);
    save_to_submit_buf(p.event, &returned_major, sizeof(unsigned int), 1);
    save_str_to_buf(p.event, char_device_name, 2);
    save_to_submit_buf(p.event, &char_device_fops, sizeof(void *), 3);

    return events_perf_submit(&p, REGISTER_CHRDEV, 0);
}

static __always_inline struct pipe_buffer *get_last_write_pipe_buffer(struct pipe_inode_info *pipe)
{
    // Extract the last page buffer used in the pipe for write
    struct pipe_buffer *bufs = READ_KERN(pipe->bufs);
    unsigned int curbuf;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0))
    unsigned int nrbufs = READ_KERN(pipe->nrbufs);
    if (nrbufs > 0) {
        nrbufs--;
    }
    curbuf = (READ_KERN(pipe->curbuf) + nrbufs) & (READ_KERN(pipe->buffers) - 1);
    #else
    int head = READ_KERN(pipe->head);
    int ring_size = READ_KERN(pipe->ring_size);
    curbuf = (head - 1) & (ring_size - 1);
    #endif
#else // CORE
    struct pipe_inode_info___v54 *legacy_pipe = (struct pipe_inode_info___v54 *) pipe;
    if (bpf_core_field_exists(legacy_pipe->nrbufs)) {
        unsigned int nrbufs = READ_KERN(legacy_pipe->nrbufs);
        if (nrbufs > 0) {
            nrbufs--;
        }
        curbuf = (READ_KERN(legacy_pipe->curbuf) + nrbufs) & (READ_KERN(legacy_pipe->buffers) - 1);
    } else {
        int head = READ_KERN(pipe->head);
        int ring_size = READ_KERN(pipe->ring_size);
        curbuf = (head - 1) & (ring_size - 1);
    }
#endif

    struct pipe_buffer *current_buffer = get_node_addr(bufs, curbuf);
    return current_buffer;
}

SEC("kprobe/do_splice")
TRACE_ENT_FUNC(do_splice, DIRTY_PIPE_SPLICE);

SEC("kretprobe/do_splice")
int BPF_KPROBE(trace_ret_do_splice)
{
// The Dirty Pipe vulnerability exist in the kernel since version 5.8, so there is not use to do
// logic if version is too old. In non-CORE, it will even mean using defines which are not available
// in the kernel headers, which will cause bugs.
#if !defined(CORE) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
    del_args(DIRTY_PIPE_SPLICE);
    return 0;
#else
    #ifdef CORE
    // Check if field of struct exist to determine kernel version - some fields change between
    // versions. In version 5.8 of the kernel, the field "high_zoneidx" changed its name to
    // "highest_zoneidx". This means that the existence of the field "high_zoneidx" can indicate
    // that the kernel version is lower than v5.8
    struct alloc_context *check_508;
    if (bpf_core_field_exists(check_508->high_zoneidx)) {
        del_args(DIRTY_PIPE_SPLICE);
        return 0;
    }
    #endif // CORE

    args_t saved_args;
    if (load_args(&saved_args, DIRTY_PIPE_SPLICE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(DIRTY_PIPE_SPLICE);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DIRTY_PIPE_SPLICE, p.event))
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
    unsigned int out_pipe_last_buffer_flags = READ_KERN(last_write_page_buffer->flags);
    if ((out_pipe_last_buffer_flags & PIPE_BUF_FLAG_CAN_MERGE) == 0) {
        return 0;
    }

    struct file *in_file = (struct file *) saved_args.args[0];
    struct inode *in_inode = READ_KERN(in_file->f_inode);
    u64 in_inode_number = READ_KERN(in_inode->i_ino);
    unsigned short in_file_type = READ_KERN(in_inode->i_mode) & S_IFMT;
    void *in_file_path = get_path_str(GET_FIELD_ADDR(in_file->f_path));
    size_t write_len = (size_t) saved_args.args[4];

    loff_t *off_in_addr = (loff_t *) saved_args.args[1];
    // In kernel v5.10 the pointer passed was no longer of the user, so flexibility is needed to
    // read it
    loff_t off_in;
    #ifndef CORE
        #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    off_in = READ_USER(*off_in_addr);
        #else
    off_in = READ_KERN(*off_in_addr);
        #endif
    #else  // CORE
    //
    // Check if field of struct exist to determine kernel version - some fields change between
    // versions. Field 'data' of struct 'public_key_signature' was introduced between v5.9 and
    // v5.10, so its existence might be used to determine whether the current version is older than
    // 5.9 or newer than 5.10.
    //
    // https://lore.kernel.org/stable/20210821203108.215937-1-rafaeldtinoco@gmail.com/
    //
    struct public_key_signature *check;
    if (!bpf_core_field_exists(check->data)) { // version < v5.10
        off_in = READ_USER(*off_in_addr);
    } else { // version >= v5.10
        off_in = READ_KERN(*off_in_addr);
    }
    #endif // CORE

    struct inode *out_inode = READ_KERN(out_file->f_inode);
    u64 out_inode_number = READ_KERN(out_inode->i_ino);

    // Only last page written to pipe is vulnerable from the end of written data
    loff_t next_exposed_data_offset_in_out_pipe_last_page =
        READ_KERN(last_write_page_buffer->offset) + READ_KERN(last_write_page_buffer->len);
    size_t in_file_size = READ_KERN(in_inode->i_size);
    size_t exposed_data_len = (PAGE_SIZE - 1) - next_exposed_data_offset_in_out_pipe_last_page;
    loff_t current_file_offset = off_in + write_len;
    if (current_file_offset + exposed_data_len > in_file_size) {
        exposed_data_len = in_file_size - current_file_offset - 1;
    }

    save_to_submit_buf(p.event, &in_inode_number, sizeof(u64), 0);
    save_to_submit_buf(p.event, &in_file_type, sizeof(unsigned short), 1);
    save_str_to_buf(p.event, in_file_path, 2);
    save_to_submit_buf(p.event, &current_file_offset, sizeof(loff_t), 3);
    save_to_submit_buf(p.event, &exposed_data_len, sizeof(size_t), 4);
    save_to_submit_buf(p.event, &out_inode_number, sizeof(u64), 5);
    save_to_submit_buf(p.event, &out_pipe_last_buffer_flags, sizeof(unsigned int), 6);

    return events_perf_submit(&p, DIRTY_PIPE_SPLICE, 0);
#endif     // CORE && Version < 5.8
}

SEC("kprobe/do_init_module")
int BPF_KPROBE(trace_do_init_module)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    kmod_data_t module_data = {0};

    // get pointers before init
    struct module *mod = (struct module *) PT_REGS_PARM1(ctx);
    struct list_head ls = READ_KERN(mod->list);
    struct list_head *prev = ls.prev;
    struct list_head *next = ls.next;

    module_data.prev = (u64) prev;
    module_data.next = (u64) next;

    // save string values on buffer for kretprobe
    bpf_probe_read_str(&module_data.name, MODULE_NAME_LEN, (void *) READ_KERN(mod->name));
    bpf_probe_read_str(
        &module_data.version, MODULE_VERSION_MAX_LENGTH, (void *) READ_KERN(mod->version));
    bpf_probe_read_str(
        &module_data.srcversion, MODULE_SRCVERSION_MAX_LENGTH, (void *) READ_KERN(mod->srcversion));

    // save module_data for kretprobe
    bpf_map_update_elem(&module_init_map, &p.event->context.task.host_tid, &module_data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_init_module")
int BPF_KPROBE(trace_ret_do_init_module)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;
    if (!should_submit(DO_INIT_MODULE, p.event))
        return 0;

    kmod_data_t *orig_module_data =
        bpf_map_lookup_elem(&module_init_map, &p.event->context.task.host_tid);
    if (orig_module_data == NULL) {
        return 0;
    }

    // get next of original previous
    struct list_head *orig_prev_ptr = (struct list_head *) (orig_module_data->prev);
    u64 orig_prev_next_addr = (u64) READ_KERN(orig_prev_ptr->next);
    // get previous of original next
    struct list_head *orig_next_ptr = (struct list_head *) (orig_module_data->next);
    u64 orig_next_prev_addr = (u64) READ_KERN(orig_next_ptr->prev);

    // save strings to buf
    save_str_to_buf(p.event, &orig_module_data->name, 0);
    save_str_to_buf(p.event, &orig_module_data->version, 1);
    save_str_to_buf(p.event, &orig_module_data->srcversion, 2);
    // save pointers to buf
    save_to_submit_buf(p.event, &(orig_module_data->prev), sizeof(u64), 3);
    save_to_submit_buf(p.event, &(orig_module_data->next), sizeof(u64), 4);
    save_to_submit_buf(p.event, &orig_prev_next_addr, sizeof(u64), 5);
    save_to_submit_buf(p.event, &orig_next_prev_addr, sizeof(u64), 6);

    events_perf_submit(&p, DO_INIT_MODULE, 0);

    // delete module data from map after it was used
    bpf_map_delete_elem(&module_init_map, &p.event->context.task.host_tid);

    return 0;
}

SEC("kprobe/load_elf_phdrs")
int BPF_KPROBE(trace_load_elf_phdrs)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &p.event->context.task.host_pid);
    if (unlikely(proc_info == NULL)) {
        // entry should exist in proc_map (init_program_data should have set it otherwise)
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    struct file *loaded_elf = (struct file *) PT_REGS_PARM2(ctx);
    const char *elf_pathname = (char *) get_path_str(GET_FIELD_ADDR(loaded_elf->f_path));

    // The interpreter field will be updated for any loading of an elf, both for the binary
    // and for the interpreter. Because the interpreter is loaded only after the executed elf is
    // loaded, the value of the executed binary should be overridden by the interpreter.
    size_t sz = sizeof(proc_info->interpreter.pathname);
    bpf_probe_read_str(proc_info->interpreter.pathname, sz, elf_pathname);
    proc_info->interpreter.device = get_dev_from_file(loaded_elf);
    proc_info->interpreter.inode = get_inode_nr_from_file(loaded_elf);
    proc_info->interpreter.ctime = get_ctime_nanosec_from_file(loaded_elf);

    if (should_submit(LOAD_ELF_PHDRS, p.event)) {
        save_str_to_buf(p.event, (void *) elf_pathname, 0);
        save_to_submit_buf(p.event, &proc_info->interpreter.device, sizeof(dev_t), 1);
        save_to_submit_buf(p.event, &proc_info->interpreter.inode, sizeof(unsigned long), 2);

        events_perf_submit(&p, LOAD_ELF_PHDRS, 0);
    }

    return 0;
}

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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(HOOKED_PROC_FOPS, p.event))
        return 0;

    struct file_operations *fops = (struct file_operations *) READ_KERN(f_inode->i_fop);
    if (fops == NULL)
        return 0;

    unsigned long iterate_shared_addr = (unsigned long) READ_KERN(fops->iterate_shared);
    unsigned long iterate_addr = (unsigned long) READ_KERN(fops->iterate);
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

    save_u64_arr_to_buf(p.event, (const u64 *) fops_addresses, 2, 0);
    events_perf_submit(&p, HOOKED_PROC_FOPS, 0);
    return 0;
}

SEC("raw_tracepoint/task_rename")
int tracepoint__task__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(TASK_RENAME, p.event))
        return 0;

    struct task_struct *tsk = (struct task_struct *) ctx->args[0];
    char old_name[TASK_COMM_LEN];
    bpf_probe_read_str(&old_name, TASK_COMM_LEN, tsk->comm);
    const char *new_name = (const char *) ctx->args[1];

    save_str_to_buf(p.event, (void *) old_name, 0);
    save_str_to_buf(p.event, (void *) new_name, 1);

    return events_perf_submit(&p, TASK_RENAME, 0);
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(trace_security_inode_rename)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_RENAME, p.event))
        return 0;

    struct dentry *old_dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *) PT_REGS_PARM4(ctx);

    void *old_dentry_path = get_dentry_path_str(old_dentry);
    save_str_to_buf(p.event, old_dentry_path, 0);
    void *new_dentry_path = get_dentry_path_str(new_dentry);
    save_str_to_buf(p.event, new_dentry_path, 1);
    return events_perf_submit(&p, SECURITY_INODE_RENAME, 0);
}

SEC("kprobe/kallsyms_lookup_name")
TRACE_ENT_FUNC(kallsyms_lookup_name, KALLSYMS_LOOKUP_NAME);

SEC("kretprobe/kallsyms_lookup_name")
int BPF_KPROBE(trace_ret_kallsyms_lookup_name)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, KALLSYMS_LOOKUP_NAME) != 0)
        return 0;
    del_args(KALLSYMS_LOOKUP_NAME);

    if (!should_submit(KALLSYMS_LOOKUP_NAME, p.event))
        return 0;

    char *name = (char *) saved_args.args[0];
    unsigned long address = PT_REGS_RC(ctx);

    save_str_to_buf(p.event, name, 0);
    save_to_submit_buf(p.event, &address, sizeof(unsigned long), 1);

    return events_perf_submit(&p, KALLSYMS_LOOKUP_NAME, 0);
}

enum signal_handling_method_e
{
#ifdef CORE
    SIG_DFL,
    SIG_IGN,
#endif
    SIG_HND = 2 // Doesn't exist in the kernel, but signifies that the method is through
                // user-defined handler
};

SEC("kprobe/do_sigaction")
int BPF_KPROBE(trace_do_sigaction)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DO_SIGACTION, p.event))
        return 0;

    // Initialize all relevant arguments values
    int sig = (int) PT_REGS_PARM1(ctx);
    u8 old_handle_method = 0, new_handle_method = 0;
    unsigned long new_sa_flags, old_sa_flags;
    void *new_sa_handler, *old_sa_handler;
    unsigned long new_sa_mask, old_sa_mask;

    // Extract old signal handler values
    struct task_struct *task = p.event->task;
    struct sighand_struct *sighand = READ_KERN(task->sighand);
    struct k_sigaction *sig_actions = &(sighand->action[0]);
    if (sig > 0 && sig < _NSIG) {
        struct k_sigaction *old_act = get_node_addr(sig_actions, sig - 1);
        old_sa_flags = READ_KERN(old_act->sa.sa_flags);
        // In 64-bit system there is only 1 node in the mask array
        old_sa_mask = READ_KERN(old_act->sa.sa_mask.sig[0]);
        old_sa_handler = READ_KERN(old_act->sa.sa_handler);
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
        new_sa_flags = READ_KERN(new_sigaction->sa_flags);
        // In 64-bit system there is only 1 node in the mask array
        new_sa_mask = READ_KERN(new_sigaction->sa_mask.sig[0]);
        new_sa_handler = READ_KERN(new_sigaction->sa_handler);
        if (new_sa_handler >= (void *) SIG_HND)
            new_handle_method = SIG_HND;
        else {
            new_handle_method = (u8) (new_sa_handler && 0xFF);
            new_sa_handler = NULL;
        }
    }

    save_to_submit_buf(p.event, &sig, sizeof(int), 0);
    save_to_submit_buf(p.event, &new_act_initialized, sizeof(bool), 1);
    if (new_act_initialized) {
        save_to_submit_buf(p.event, &new_sa_flags, sizeof(unsigned long), 2);
        save_to_submit_buf(p.event, &new_sa_mask, sizeof(unsigned long), 3);
        save_to_submit_buf(p.event, &new_handle_method, sizeof(u8), 4);
        save_to_submit_buf(p.event, &new_sa_handler, sizeof(void *), 5);
    }
    save_to_submit_buf(p.event, &old_act_initialized, sizeof(bool), 6);
    save_to_submit_buf(p.event, &old_sa_flags, sizeof(unsigned long), 7);
    save_to_submit_buf(p.event, &old_sa_mask, sizeof(unsigned long), 8);
    save_to_submit_buf(p.event, &old_handle_method, sizeof(u8), 9);
    save_to_submit_buf(p.event, &old_sa_handler, sizeof(void *), 10);

    return events_perf_submit(&p, DO_SIGACTION, 0);
}

static __always_inline int common_utimes(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(VFS_UTIMES, p.event))
        return 0;

    struct path *path = (struct path *) PT_REGS_PARM1(ctx);
    struct timespec64 *times = (struct timespec64 *) PT_REGS_PARM2(ctx);

    void *path_str = get_path_str(path);

    struct dentry *dentry = READ_KERN(path->dentry);
    u64 inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    u64 atime = get_time_nanosec_timespec(times);
    u64 mtime = get_time_nanosec_timespec(&times[1]);

    save_str_to_buf(p.event, path_str, 0);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 1);
    save_to_submit_buf(p.event, &inode_nr, sizeof(u64), 2);
    save_to_submit_buf(p.event, &atime, sizeof(u64), 3);
    save_to_submit_buf(p.event, &mtime, sizeof(u64), 4);

    return events_perf_submit(&p, VFS_UTIMES, 0);
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
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DO_TRUNCATE, p.event))
        return 0;

    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    u64 length = (long) PT_REGS_PARM3(ctx);

    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &length, sizeof(u64), 3);

    return events_perf_submit(&p, DO_TRUNCATE, 0);
}

SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM2(ctx);

    // check if regular file. otherwise don't save the file_mod_key_t in file_modification_map.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.device, file_info.inode};
    int op = FILE_MODIFICATION_SUBMIT;

    bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);

    return 0;
}

SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.device, file_info.inode};

    bpf_map_delete_elem(&file_modification_map, &file_mod_key);

    return 0;
}

static __always_inline int common_file_modification_ent(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(FILE_MODIFICATION, p.event))
        return 0;

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

static __always_inline int common_file_modification_ret(struct pt_regs *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;
    del_args(FILE_MODIFICATION);

    struct file *file = (struct file *) saved_args.args[0];
    u64 old_ctime = saved_args.args[1];

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.device, file_info.inode};

    int *op = bpf_map_lookup_elem(&file_modification_map, &file_mod_key);
    if (op == NULL || *op == FILE_MODIFICATION_SUBMIT) {
        // we should submit the event once and mark as done.
        int op = FILE_MODIFICATION_DONE;
        bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);
    } else {
        // no need to submit. return.
        return 0;
    }

    save_str_to_buf(p.event, file_info.pathname_p, 0);
    save_to_submit_buf(p.event, &file_info.device, sizeof(dev_t), 1);
    save_to_submit_buf(p.event, &file_info.inode, sizeof(unsigned long), 2);
    save_to_submit_buf(p.event, &old_ctime, sizeof(u64), 3);
    save_to_submit_buf(p.event, &file_info.ctime, sizeof(u64), 4);

    events_perf_submit(&p, FILE_MODIFICATION, 0);

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
#ifndef CORE
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    return common_file_modification_ent(ctx);
    #endif
#else /* CORE */
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (bpf_core_field_exists(file->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ent(ctx);
    }
#endif

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
#ifndef CORE
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    return common_file_modification_ent(ctx);
    #endif
#else /* CORE */
    args_t saved_args;
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;

    struct file *file = (struct file *) saved_args.args[0];
    if (bpf_core_field_exists(file->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ent(ctx);
    }
#endif

    return 0;
}

SEC("kprobe/inotify_find_inode")
TRACE_ENT_FUNC(inotify_find_inode, INOTIFY_WATCH);

SEC("kretprobe/inotify_find_inode")
int BPF_KPROBE(trace_ret_inotify_find_inode)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, INOTIFY_WATCH) != 0)
        return 0;
    del_args(INOTIFY_WATCH);

    struct path *path = (struct path *) saved_args.args[1];

    void *path_str = get_path_str(path);

    struct dentry *dentry = READ_KERN(path->dentry);
    u64 inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);

    save_str_to_buf(p.event, path_str, 0);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&p, INOTIFY_WATCH, 0);
}

SEC("kprobe/exec_binprm")
TRACE_ENT_FUNC(exec_binprm, EXEC_BINPRM);

SEC("kretprobe/exec_binprm")
int BPF_KPROBE(trace_ret_exec_binprm)
{
    args_t saved_args;
    if (load_args(&saved_args, EXEC_BINPRM) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(EXEC_BINPRM);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(PROCESS_EXECUTION_FAILED, p.event))
        return 0;

    int ret_val = PT_REGS_RC(ctx);
    if (ret_val == 0)
        return 0; // not interested of successful execution - for that we have sched_process_exec

    struct linux_binprm *bprm = (struct linux_binprm *) saved_args.args[0];
    if (bprm == NULL) {
        return -1;
    }

    struct file *file = get_file_ptr_from_bprm(bprm);

    const char *path = get_binprm_filename(bprm);
    save_str_to_buf(p.event, (void *) path, 0);

    void *binary_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    save_str_to_buf(p.event, binary_path, 1);

    dev_t binary_device_id = get_dev_from_file(file);
    save_to_submit_buf(p.event, &binary_device_id, sizeof(dev_t), 2);

    unsigned long binary_inode_number = get_inode_nr_from_file(file);
    save_to_submit_buf(p.event, &binary_inode_number, sizeof(unsigned long), 3);

    u64 binary_ctime = get_ctime_nanosec_from_file(file);
    save_to_submit_buf(p.event, &binary_ctime, sizeof(u64), 4);

    umode_t binary_inode_mode = get_inode_mode_from_file(file);
    save_to_submit_buf(p.event, &binary_inode_mode, sizeof(umode_t), 5);

    const char *interpreter_path = get_binprm_interp(bprm);
    save_str_to_buf(p.event, (void *) interpreter_path, 6);

    bpf_tail_call(ctx, &prog_array, TAIL_EXEC_BINPRM1);
    return -1;
}

SEC("kretprobe/trace_ret_exec_binprm1")
int BPF_KPROBE(trace_ret_exec_binprm1)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    struct file *stdin_file = get_struct_file_from_fd(0);

    unsigned short stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
    save_to_submit_buf(p.event, &stdin_type, sizeof(unsigned short), 7);

    void *stdin_path = get_path_str(GET_FIELD_ADDR(stdin_file->f_path));
    save_str_to_buf(p.event, stdin_path, 8);

    int kernel_invoked = (get_task_parent_flags(task) & PF_KTHREAD) ? 1 : 0;
    save_to_submit_buf(p.event, &kernel_invoked, sizeof(int), 9);

    bpf_tail_call(ctx, &prog_array, TAIL_EXEC_BINPRM2);
    return -1;
}

SEC("kretprobe/trace_ret_exec_binprm2")
int BPF_KPROBE(trace_ret_exec_binprm2)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    syscall_data_t *sys = &p.task_info->syscall_data;
    save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[1], 10); // userspace argv

    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[2], 11); // userspace envp
    }

    int ret = PT_REGS_RC(ctx); // needs to be int

    return events_perf_submit(&p, PROCESS_EXECUTION_FAILED, ret);
}

// clang-format off

// Network Packets (works from ~5.2 and beyond)

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 0) || defined(CORE)) || defined(RHEL_RELEASE_CODE)

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

static __always_inline bool is_family_supported(struct socket *sock)
{
    struct sock *sk = (void *) BPF_READ(sock, sk);
    struct sock_common *common = (void *) sk;
    u8 family = BPF_READ(common, skc_family);

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

static __always_inline bool is_socket_supported(struct socket *sock)
{
    struct sock *sk = (void *) BPF_READ(sock, sk);
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

static __always_inline u64 sizeof_net_event_context_t(void)
{
    return sizeof(net_event_context_t) - sizeof(net_event_contextmd_t);
}

static __always_inline void set_net_task_context(event_data_t *event, net_task_context_t *netctx)
{
    netctx->task = event->task;
    netctx->matched_policies = event->context.matched_policies;
    netctx->syscall = event->context.syscall;
    __builtin_memset(&netctx->taskctx, 0, sizeof(task_context_t));
    __builtin_memcpy(&netctx->taskctx, &event->context.task, sizeof(task_context_t));
}

static __always_inline enum event_id_e net_packet_to_net_event(net_packet_t packet_type)
{
    switch (packet_type) {
        case CAP_NET_PACKET:
            return NET_PACKET_CAP_BASE;
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

static __always_inline int should_submit_net_event(net_event_context_t *neteventctx,
                                                   net_packet_t packet_type)
{
    // configure network events that should be sent to userland
    if (neteventctx->md.submit & packet_type)
        return 1;

    if (should_submit_by_ctx(net_packet_to_net_event(packet_type), &(neteventctx->eventctx))) {
        neteventctx->md.submit |= packet_type;
        // done, result cached for later.
        return 1;
    }
    return 0;
}

static __always_inline int should_capture_net_event(net_event_context_t *neteventctx,
                                                    net_packet_t packet_type)
{
    if (neteventctx->md.captured) // already captured
        return 0;

    return should_submit_net_event(neteventctx, packet_type);
}

//
// Protocol parsing functions
//

#define CGROUP_SKB_HANDLE_FUNCTION(name)                                       \
static __always_inline u32 cgroup_skb_handle_##name(                           \
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

static __always_inline u32 cgroup_skb_submit(void *map,
                                             struct __sk_buff *ctx,
                                             net_event_context_t *neteventctx,
                                             u32 event_type,
                                             u32 size)
{
    u64 flags = BPF_F_CURRENT_CPU;

    size = size > FULL ? FULL : size;
    switch (size) {
        case HEADERS:
            size = neteventctx->md.header_size;
            break;
        case FULL:
            size = ctx->len;
            break;
        default:
            size += neteventctx->md.header_size;       // add headers size
            size = size > ctx->len ? ctx->len : size;  // check limits
            break;
    }

    flags |= (u64) size << 32;
    neteventctx->bytes = size + sizeof(u32);

    // set the event type before submitting event
    neteventctx->eventctx.eventid = event_type;

    return bpf_perf_event_output(ctx,
                                 map,
                                 flags,
                                 neteventctx,
                                 sizeof_net_event_context_t());
}

#define cgroup_skb_submit_event(a,b,c,d) cgroup_skb_submit(&events,a,b,c,d)

static __always_inline u32 cgroup_skb_capture_event(struct __sk_buff *ctx,
                                                    net_event_context_t *neteventctx,
                                                    u32 event_type)
{
    int zero = 0;

    // pick network config map to know requested capture length
    netconfig_entry_t *nc = bpf_map_lookup_elem(&netconfig_map, &zero);
    if (nc == NULL)
        return 0;

    return cgroup_skb_submit(&net_cap_events,
                             ctx,
                             neteventctx,
                             event_type,
                             nc->capture_length);
}

// capture packet a single time (if passing through multiple protocols being submitted to userland)
#define cgroup_skb_capture() {                                                                     \
    if (should_submit_net_event(neteventctx, CAP_NET_PACKET)) {                                    \
        if (neteventctx->md.captured == 0) { /* do not capture the same packet twice */            \
            cgroup_skb_capture_event(ctx, neteventctx, NET_PACKET_CAP_BASE);                       \
            neteventctx->md.captured = 1;                                                          \
        }                                                                                          \
    }                                                                                              \
}

//
// Socket creation and socket <=> task context updates
//

SEC("kprobe/sock_alloc_file")
int BPF_KPROBE(trace_sock_alloc_file)
{
    // runs every time a socket is created (entry)

    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    if (!is_family_supported(sock))
        return 0;

    if (!is_socket_supported(sock))
        return 0;

    // initialize program data

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct entry entry = {0};

    // save args for retprobe
    entry.args[0] = PT_REGS_PARM1(ctx); // struct socket *sock

    entry.args[1] = PT_REGS_PARM2(ctx); // int flags
    entry.args[2] = PT_REGS_PARM2(ctx); // char *dname

    // prepare for kretprobe using entrymap
    u32 host_tid = p.event->context.task.host_tid;
    bpf_map_update_elem(&entrymap, &host_tid, &entry, BPF_ANY);

    return 0;
}

SEC("kretprobe/sock_alloc_file")
int BPF_KRETPROBE(trace_ret_sock_alloc_file)
{
    // runs every time a socket is created (return)

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
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

    u64 inode = BPF_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save context to further create an event when no context exists
    net_task_context_t netctx = {0};
    set_net_task_context(p.event, &netctx);

    // update inodemap correlating inode <=> task
    bpf_map_update_elem(&inodemap, &inode, &netctx, BPF_ANY);

    return 0;
}

static __always_inline u32 security_socket_send_recv_msg(struct socket *sock, event_data_t *event)
{
    if (!is_family_supported(sock))
        return 0;

    if (!is_socket_supported(sock))
        return 0;

    struct file *sock_file = BPF_READ(sock, file);
    if (!sock_file)
        return 0;

    u64 inode = BPF_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save updated context to the inode map (inode <=> task ctx relation)
    net_task_context_t netctx = {0};
    set_net_task_context(event, &netctx);
    bpf_map_update_elem(&inodemap, &inode, &netctx, BPF_ANY);

    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(trace_security_socket_recvmsg)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    return security_socket_send_recv_msg(sock, p.event);
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(trace_security_socket_sendmsg)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    return security_socket_send_recv_msg(sock, p.event);
}

//
// Socket Ingress/Egress eBPF program loader (right before and right after eBPF)
//

SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(cgroup_bpf_run_filter_skb)
{
    // runs BEFORE the CGROUP/SKB eBPF program

    void *cgrpctxmap = NULL;

    int type = PT_REGS_PARM3(ctx);
    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
            cgrpctxmap = &cgrpctxmap_in;
            break;
        case BPF_CGROUP_INET_EGRESS:
            cgrpctxmap = &cgrpctxmap_eg;
            break;
        default:
            return 0; // other attachment type, return fast
    }

    struct sock *sk = (void *) PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (void *) PT_REGS_PARM2(ctx);

    struct sock_common *common = (void *) sk;
    u8 family = BPF_READ(common, skc_family);

    switch (family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // return fast for unsupported socket families
    }

    //
    // EVENT CONTEXT (from current task)
    //

    u32 zero = 0;
    event_data_t *e = bpf_map_lookup_elem(&net_heap_event, &zero);
    if (unlikely(e == NULL))
        return 0;
    scratch_t *s = bpf_map_lookup_elem(&net_heap_scratch, &zero);
    if (unlikely(s == NULL))
        return 0;

    program_data_t p = {
        .event = e,
        .scratch = s,
    };
    if (!init_program_data(&p, ctx))
        return 0;

    // obtain socket inode
    u64 inode = BPF_READ(sk, sk_socket, file, f_inode, i_ino);
    if (inode == 0)
        return 0; // e.g. vhost kernel threads might not have an inode

    // pick network context from the inodemap (inode <=> task)
    net_task_context_t *netctx = bpf_map_lookup_elem(&inodemap, &inode);
    if (!netctx)
        return 0; // e.g. task isn't being traced

    //
    // PREPARE SKG PROGRAM EVENT CONTEXT (cgrpctxmap value)
    //

    // Prepare [event_context_t][args1,arg2,arg3...] to be sent by cgroup/skb
    // program. The [...] part of the event can't use existing per-cpu submit
    // buffer helpers because the time in between this kprobe fires and the
    // cgroup/skb program runs might be suffer a preemption.

    net_event_context_t neteventctx = {0}; // to be sent by cgroup/skb program
    event_context_t *eventctx = &neteventctx.eventctx;

    // copy orig task ctx (from the netctx) to event ctx and build the rest
    __builtin_memcpy(&eventctx->task, &netctx->taskctx, sizeof(task_context_t));
    eventctx->ts = p.event->context.ts;                     // copy timestamp from current ctx
    eventctx->argnum = 1;                                   // 1 argument (add more if needed)
    eventctx->eventid = NET_PACKET_IP;                      // will be changed in skb program
    eventctx->stack_id = 0;                                 // no stack trace
    eventctx->processor_id = p.event->context.processor_id; // copy from current ctx
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
            l3_size = get_type_size(struct iphdr);
            break;
        case PF_INET6:
            eventctx->retval |= family_ipv6;
            l3_size = get_type_size(struct ipv6hdr);
            break;
        default:
            return 1;
    }
    // ... through event ctx ret val

    // read IP/IPv6 headers

    void *data_ptr = NULL;
    u16 mac_len = BPF_READ(skb, mac_len);
    if (!mac_len) {
        data_ptr = BPF_READ(skb, data); // no L2 header present in skb
    } else {
        data_ptr = BPF_READ(skb, head);
        u16 nethead = BPF_READ(skb, network_header);
        data_ptr += nethead;
    }
    bpf_core_read(nethdrs, l3_size, data_ptr);

    // prepare the indexer with IP/IPv6 headers

    u8 proto = 0;

    indexer_t indexer = {0};
    indexer.ts = BPF_READ(skb, tstamp);

    switch (family) {
        case PF_INET:
            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

           if (nethdrs->iphdrs.iphdr.ihl > 5) { // re-read IP header if needed
                l3_size -= get_type_size(struct iphdr);
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

            // add IPv4 header items to indexer
            indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
            indexer.ip_saddr.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
            indexer.ip_daddr.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
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

            // add IPv6 header items to indexer
            __builtin_memcpy(&indexer.ip_saddr.in6_u, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
            __builtin_memcpy(&indexer.ip_daddr.in6_u, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
            break;

        default:
            return 1;
    }

    //
    // LINK CONTENT INDEXER TO EVENT CONTEXT
    //

    neteventctx.bytes = 0; // event arg size: no payload by default (changed inside skb prog)

    // TODO: log collisions
    bpf_map_update_elem(cgrpctxmap, &indexer, &neteventctx, BPF_NOEXIST);

    return 0;
}

//
// SKB eBPF programs
//

static __always_inline u32 cgroup_skb_generic(struct __sk_buff *ctx, void *cgrpctxmap)
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
            size = get_type_size(struct iphdr);
            break;
        case PF_INET6:
            dest = &nethdrs->iphdrs.ipv6hdr;
            size = get_type_size(struct ipv6hdr);
            break;
        default:
            return 1; // verifier
    }

    // load layer 3 headers (for cgrpctxmap key/indexer)

    if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1)) {
        return 1;
    }

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
                size -= get_type_size(struct iphdr);
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

            // add IPv6 header items to indexer
            indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
            indexer.ip_saddr.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
            indexer.ip_daddr.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
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
            __builtin_memcpy(&indexer.ip_saddr.in6_u, &nethdrs->iphdrs.ipv6hdr.saddr.in6_u, 4 * sizeof(u32));
            __builtin_memcpy(&indexer.ip_daddr.in6_u, &nethdrs->iphdrs.ipv6hdr.daddr.in6_u, 4 * sizeof(u32));
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
                    size = get_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = get_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMP:
                    dest = &nethdrs->protohdrs.icmphdr;
                    size = 0; // will be added later, last function
                    break;
                default:
                    return 1; // other protocols are not an error
            }
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
                    size = get_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = get_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMPV6:
                    dest = &nethdrs->protohdrs.icmp6hdr;
                    size = 0; // will be added later, last function
                    break;
                default:
                    return 1; // other protocols are not an error
            }
            break;

        default:
            return 1; // verifier needs
    }

    if (!dest)
        return 1; // satisfy verifier for clang-12 generated binaries

    // fastpath: submit the IP base event

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_IP, HEADERS);

    // fastpath: capture all packets if filtered pcap-option is not set

    u32 zero = 0;
    netconfig_entry_t *nc = bpf_map_lookup_elem(&netconfig_map, &zero);
    if (nc == NULL)
        return 0;

    if (!(nc->capture_options & NET_CAP_OPT_FILTERED))
        cgroup_skb_capture(); // will avoid extra lookups further if not needed

    neteventctx->md.header_size += size; // add header size to offset

    // load layer 4 protocol headers

    if (size) {
        if (bpf_skb_load_bytes_relative(ctx,
                                        prev_hdr_size,
                                        dest, size,
                                        BPF_HDR_START_NET))
            return 1;
    }

   // call protocol handlers (for more base events to be sent)

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

    // capture IPv4/IPv6 packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_capture();

    return 1;
}

//
// GUESS L7 NETWORK PROTOCOLS (http, dns, etc)
//

// when guessing by src/dst ports, declare at network.h

// when guessing through l7 layer, here

static __always_inline int net_l7_is_http(struct __sk_buff *skb, u32 l7_off)
{
    char http_min_str[http_min_len];
    __builtin_memset((void *) &http_min_str, 0, sizeof(char) * http_min_len);

    // load first http_min_len bytes from layer 7 in packet.
    if (bpf_skb_load_bytes(skb, l7_off, http_min_str, http_min_len) < 0) {
        return 0; // failed loading data into http_min_str - return.
    }

    // check if HTTP response
    if (has_prefix("HTTP/", http_min_str, 6)) {
        return proto_http_resp;
    }

    // check if HTTP request
    if (has_prefix("GET ", http_min_str, 5)    ||
        has_prefix("POST ", http_min_str, 6)   ||
        has_prefix("PUT ", http_min_str, 5)    ||
        has_prefix("DELETE ", http_min_str, 8) ||
        has_prefix("HEAD ", http_min_str, 6)) {
        return proto_http_req;
    }

    return 0;
}

//
// SUPPORTED L4 NETWORK PROTOCOL (tcp, udp, icmp) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp)
{
    // check flag for dynamic header size (TCP: data offset flag)

    if (nethdrs->protohdrs.tcphdr.doff > 5) { // offset flag set
        u32 doff = nethdrs->protohdrs.tcphdr.doff * (32 / 8);
        neteventctx->md.header_size -= get_type_size(struct tcphdr);
        neteventctx->md.header_size += doff;
    }

    // submit TCP base event if needed (only headers)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_TCP, HEADERS);

    // fastpath: return if no other L7 network events

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS) &&
        !should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        goto capture;

    // guess layer 7 protocols

    u16 source = bpf_ntohs(nethdrs->protohdrs.tcphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.tcphdr.dest);

    // guess by src/dst ports

    switch (source < dest ? source : dest) {
        case TCP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_tcp_dns);
    }

    // guess by analyzing payload

    int http_proto = net_l7_is_http(ctx, neteventctx->md.header_size);
    if (http_proto) {
        neteventctx->eventctx.retval |= http_proto;
        return CGROUP_SKB_HANDLE(proto_tcp_http);
    }

    // continue with net_l7_is_protocol_xxx
    // ...

capture:
    // capture IP or TCP packets (filtered)
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_capture_net_event(neteventctx, SUB_NET_PACKET_TCP)) {
        cgroup_skb_capture();
    }

    return 1; // NOTE: might block TCP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp)
{
    // submit UDP base event if needed (only headers)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_UDP, HEADERS);

    // fastpath: return if no other L7 network events

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS) &&
        !should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        goto capture;

    // guess layer 7 protocols

    u16 source = bpf_ntohs(nethdrs->protohdrs.udphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.udphdr.dest);

    // guess by src/dst ports

    switch (source < dest ? source : dest) {
        case UDP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_udp_dns);
    }

    // guess by analyzing payload
    // ...

    // continue with net_l7_is_protocol_xxx
    // ...

capture:
    // capture IP or UDP packets (filtered)
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

#endif
