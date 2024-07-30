#ifndef __COMMON_PROBES_H__
#define __COMMON_PROBES_H__

#include <vmlinux.h>

#include <bpf/bpf_tracing.h>

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

#endif
