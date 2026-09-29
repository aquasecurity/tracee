#ifndef __COMMON_FD_PATH_H__
#define __COMMON_FD_PATH_H__

#include <types.h>

// Lets an entry probe skip program data setup when the enrichment is disabled.
statfunc bool fd_paths_enabled(void)
{
    u32 zero = 0;
    config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
    return config != NULL && (config->options & OPT_TRANSLATE_FD_FILEPATH);
}

statfunc void clear_fd_path(task_info_t *task_info, u32 tid)
{
    // Only a resolved capture has stored a snapshot.
    if (task_info->fd_path_status == FD_PATH_RESOLVED)
        bpf_map_delete_elem(&fd_arg_path_map, &tid);
    task_info->fd_path_status = FD_PATH_NONE;
}

statfunc void reserve_fd_path(program_data_t *p)
{
    if ((p->config->options & OPT_TRANSLATE_FD_FILEPATH) &&
        p->task_info->fd_path_status != FD_PATH_NONE) {
        p->event->args_buf.offset = sizeof(fd_path_header_t);
        p->event->fd_path_reserved = true;
    }
}

statfunc void append_fd_path(program_data_t *p)
{
    task_info_t *task_info = p->task_info;
    syscall_data_t *sys = &task_info->syscall_data;
    if (!p->event->fd_path_reserved || task_info->fd_path_status == FD_PATH_NONE ||
        p->event->context.eventid != sys->id || p->event->context.ts != sys->ts)
        return;

    args_buffer_t *buf = &p->event->args_buf;
    u32 offset = buf->offset;
    if (offset < sizeof(fd_path_header_t) || offset > ARGS_BUF_SIZE)
        return;

    fd_path_header_t header = {
        .version = 1,
        .arg_index = task_info->fd_path_arg_index,
        .status = task_info->fd_path_status,
        .args_size = offset - sizeof(fd_path_header_t),
    };

    if (header.status == FD_PATH_RESOLVED) {
        u32 tid = bpf_get_current_pid_tgid();
        fd_arg_path_t *snapshot = bpf_map_lookup_elem(&fd_arg_path_map, &tid);
        header.status = FD_PATH_STORAGE_ERROR;
        if (snapshot && snapshot->ts == sys->ts && snapshot->syscall == sys->id) {
            u32 size = snapshot->size;
            if (size > 1 && size <= MAX_FD_PATH_SIZE &&
                offset <= ARGS_BUF_SIZE - MAX_FD_PATH_SIZE) {
                // Keep the bound on the helper's actual size register on older
                // verifiers. The register is both read and written here.
                asm volatile("if %[size] < %[max_size] goto +1;\n"
                             "%[size] = %[max_size];\n"
                             : [size] "+r"(size)
                             : [max_size] "i"(MAX_FD_PATH_SIZE));
                if (bpf_probe_read_kernel(&buf->args[offset], size, snapshot->path) == 0) {
                    header.status = FD_PATH_RESOLVED;
                    header.path_size = size;
                    offset += size;
                }
            }
        }
    }

    if (bpf_probe_read_kernel(&buf->args[0], sizeof(header), &header) != 0)
        return;
    buf->offset = offset;
    // Set only in the event copy, after events_perf_submit updates task context.
    p->event->context.task.flags |= FD_PATH_FLAG;
}

#endif
