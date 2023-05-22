#ifndef __COMMON_ARGUMENTS_H__
#define __COMMON_ARGUMENTS_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc int save_args(args_t *, u32);
statfunc int load_args(args_t *, u32);
statfunc int del_args(u32);

// FUNCTIONS

statfunc int save_args(args_t *args, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&args_map, &id, args, BPF_ANY);

    return 0;
}

statfunc int load_args(args_t *args, u32 event_id)
{
    args_t *saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = bpf_map_lookup_elem(&args_map, &id);
    if (saved_args == 0) {
        // missed entry or not a container
        return -1;
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    return 0;
}

statfunc int del_args(u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

#endif
