#ifndef __COMMON_PROBES_H__
#define __COMMON_PROBES_H__

#include <vmlinux.h>

#include <bpf/bpf_tracing.h>

#include <common/arch.h>
#include <common/arguments.h>
#include <common/buffer.h>
#include <common/context.h>
#include <common/filtering.h>

#define TRACE_ENT_FUNC(name, id)                                                                   \
    int trace_##name(struct pt_regs *ctx)                                                          \
    {                                                                                              \
        args_t args = {};                                                                          \
        args.args[0] = PT_REGS_PARM1(ctx);                                                         \
        args.args[1] = PT_REGS_PARM2(ctx);                                                         \
        args.args[2] = PT_REGS_PARM3(ctx);                                                         \
        args.args[3] = PT_REGS_PARM4(ctx);                                                         \
        args.args[4] = PT_REGS_PARM5(ctx);                                                         \
        args.args[5] = PT_REGS_PARM6(ctx);                                                         \
                                                                                                   \
        return save_args(&args, id);                                                               \
    }

#define TRACE_RET_FUNC(name, id)                                                                   \
    int trace_ret_##name(struct pt_regs *ctx)                                                      \
    {                                                                                              \
        args_t args = {};                                                                          \
        if (load_args(&args, id) != 0)                                                             \
            return -1;                                                                             \
        del_args(id);                                                                              \
                                                                                                   \
        program_data_t p = {};                                                                     \
        if (!init_program_data(&p, ctx, id))                                                       \
            return 0;                                                                              \
                                                                                                   \
        if (!evaluate_scope_filters(&p))                                                           \
            return 0;                                                                              \
                                                                                                   \
        save_args_to_submit_buf(p.event, &args);                                                   \
                                                                                                   \
        return events_perf_submit(&p, PT_REGS_RC(ctx));                                            \
    }

#define TRACE_FUNC(name, id)                                                                       \
    SEC("kprobe/" #name)                                                                           \
    TRACE_ENT_FUNC(name, id)                                                                       \
    SEC("kretprobe/" #name)                                                                        \
    TRACE_RET_FUNC(name, id)

statfunc long long get_syscall_arg(struct task_struct *task,
                                   struct pt_regs *sys_regs,
                                   bool is_wrapped,
                                   unsigned int arg_id)
{
    struct pt_regs *regs = sys_regs;
    if (is_wrapped && get_kconfig(ARCH_HAS_SYSCALL_WRAPPER))
        regs = (struct pt_regs *) PT_REGS_PARM1(sys_regs);

    if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
        switch (arg_id) {
            case 1:
                return BPF_CORE_READ(regs, bx);
            case 2:
                return BPF_CORE_READ(regs, cx);
            case 3:
                return BPF_CORE_READ(regs, dx);
            case 4:
                return BPF_CORE_READ(regs, si);
            case 5:
                return BPF_CORE_READ(regs, di);
            case 6:
                return BPF_CORE_READ(regs, bp);
        }
#endif // bpf_target_x86
    } else {
        switch (arg_id) {
            case 1:
                return PT_REGS_PARM1_CORE_SYSCALL(regs);
            case 2:
                return PT_REGS_PARM2_CORE_SYSCALL(regs);
            case 3:
                return PT_REGS_PARM3_CORE_SYSCALL(regs);
            case 4:
                return PT_REGS_PARM4_CORE_SYSCALL(regs);
            case 5:
                return PT_REGS_PARM5_CORE_SYSCALL(regs);
            case 6:
                return PT_REGS_PARM6_CORE_SYSCALL(regs);
        }
    }

    return 0;
}

statfunc long long
get_syscall_arg1(struct task_struct *task, struct pt_regs *sys_regs, bool is_wrapped)
{
    return get_syscall_arg(task, sys_regs, is_wrapped, 1);
}

statfunc long long
get_syscall_arg2(struct task_struct *task, struct pt_regs *sys_regs, bool is_wrapped)
{
    return get_syscall_arg(task, sys_regs, is_wrapped, 2);
}

statfunc long long
get_syscall_arg3(struct task_struct *task, struct pt_regs *sys_regs, bool is_wrapped)
{
    return get_syscall_arg(task, sys_regs, is_wrapped, 3);
}

statfunc long long
get_syscall_arg4(struct task_struct *task, struct pt_regs *sys_regs, bool is_wrapped)
{
    return get_syscall_arg(task, sys_regs, is_wrapped, 4);
}

statfunc long long
get_syscall_arg5(struct task_struct *task, struct pt_regs *sys_regs, bool is_wrapped)
{
    return get_syscall_arg(task, sys_regs, is_wrapped, 5);
}

statfunc long long
get_syscall_arg6(struct task_struct *task, struct pt_regs *sys_regs, bool is_wrapped)
{
    return get_syscall_arg(task, sys_regs, is_wrapped, 6);
}

statfunc void
get_syscall_args(struct task_struct *task, struct pt_regs *sys_regs, syscall_data_t *sys)
{
    struct pt_regs *regs = get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)
                               ? (struct pt_regs *) PT_REGS_PARM1(sys_regs)
                               : sys_regs;

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
}

#define TRACE_SYS_ENT_FUNC(name, _id)                                                              \
    int trace_##name(struct pt_regs *ctx)                                                          \
    {                                                                                              \
        struct task_struct *task = (struct task_struct *) bpf_get_current_task();                  \
                                                                                                   \
        u32 tid = bpf_get_current_pid_tgid();                                                      \
        task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);                        \
        if (unlikely(task_info == NULL)) {                                                         \
            task_info = init_task_info(tid, 0);                                                    \
            if (unlikely(task_info == NULL))                                                       \
                return 0;                                                                          \
                                                                                                   \
            int zero = 0;                                                                          \
            config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);                      \
            if (unlikely(config == NULL))                                                          \
                return 0;                                                                          \
                                                                                                   \
            init_task_context(&task_info->context, task, config->options);                         \
        }                                                                                          \
                                                                                                   \
        syscall_data_t *sys = &task_info->syscall_data;                                            \
        sys->id = _id;                                                                             \
        sys->ts = get_current_time_in_ns();                                                        \
        task_info->syscall_traced = true;                                                          \
                                                                                                   \
        get_syscall_args(task, ctx, sys);                                                          \
                                                                                                   \
        bpf_tail_call(ctx, &generic_sys_enter_tails, _id);                                         \
                                                                                                   \
        return 0;                                                                                  \
    }

#define TRACE_SYS_RET_FUNC(name, _id)                                                              \
    int trace_ret_##name(struct pt_regs *ctx)                                                      \
    {                                                                                              \
        program_data_t p = {};                                                                     \
        if (!init_program_data(&p, ctx, _id))                                                      \
            return 0;                                                                              \
                                                                                                   \
        p.task_info->syscall_traced = false;                                                       \
                                                                                                   \
        if (!evaluate_scope_filters(&p))                                                           \
            goto out;                                                                              \
                                                                                                   \
        syscall_data_t *sys = &p.task_info->syscall_data;                                          \
        sys->ret = PT_REGS_RC(ctx);                                                                \
                                                                                                   \
        save_args_to_submit_buf(p.event, &sys->args);                                              \
        p.event->context.ts = sys->ts;                                                             \
        events_perf_submit(&p, sys->ret);                                                          \
                                                                                                   \
    out:                                                                                           \
        bpf_tail_call(ctx, &generic_sys_exit_tails, _id);                                          \
        return 0;                                                                                  \
    }

#define TRACE_SYSCALL(name, id)                                                                    \
    SEC("kprobe/" #name)                                                                           \
    TRACE_SYS_ENT_FUNC(name, id)                                                                   \
    SEC("kretprobe/" #name)                                                                        \
    TRACE_SYS_RET_FUNC(name, id)

#endif
