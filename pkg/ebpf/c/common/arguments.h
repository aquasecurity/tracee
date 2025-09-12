#ifndef __COMMON_ARGUMENTS_H__
#define __COMMON_ARGUMENTS_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc int save_args(args_t *, u32);
statfunc int load_args(args_t *, u32);
statfunc long del_args(u32);

// FUNCTIONS

statfunc u64 get_args_id(u32 event_id)
{
    return ((u64) event_id << 32) | (u32) bpf_get_current_pid_tgid();
}

statfunc int save_args(args_t *args, u32 event_id)
{
    u64 args_id = get_args_id(event_id);
    bpf_map_update_elem(&args_map, &args_id, args, BPF_ANY);

    return 0;
}

statfunc int load_args(args_t *args, u32 event_id)
{
    u64 args_id = get_args_id(event_id);

    args_t *saved_args = bpf_map_lookup_elem(&args_map, &args_id);
    if (!saved_args)
        return -1; // missed entry or not a container

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    return 0;
}

statfunc long del_args(u32 event_id)
{
    u64 args_id = get_args_id(event_id);

    return bpf_map_delete_elem(&args_map, &args_id);
}

#endif
