#ifndef __CAPTURE_FILTERING_H__
#define __CAPTURE_FILTERING_H__

#include <common/filesystem.h>
#include <common/consts.h>
#include <common/logging.h>
#include <common/ksymbols.h>

// CONSTANTS

#define FILTER_FILE_TYPE_START_BIT 0
#define FILTER_FILE_FD_START_BIT   16

// The following values are of the file_type_filter_t type
#define FILTER_NORMAL_FILES (1 << (FILTER_FILE_TYPE_START_BIT + 0))
#define FILTER_PIPE_FILES   (1 << (FILTER_FILE_TYPE_START_BIT + 1))
#define FILTER_SOCKET_FILES (1 << (FILTER_FILE_TYPE_START_BIT + 2))
#define FILTER_ELF_FILES    (1 << (FILTER_FILE_TYPE_START_BIT + 3))
#define FILTER_STDIN_FILES  (1 << (FILTER_FILE_FD_START_BIT + STDIN))
#define FILTER_STDOUT_FILES (1 << (FILTER_FILE_FD_START_BIT + STDOUT))
#define FILTER_STDERR_FILES (1 << (FILTER_FILE_FD_START_BIT + STDERR))

#define FILTER_FILE_TYPE_MASK ((FILTER_ELF_FILES << 1) - FILTER_NORMAL_FILES)
#define FILTER_FDS_MASK       ((FILTER_STDERR_FILES << 1) - FILTER_STDIN_FILES)

#define CAPTURE_READ_TYPE_FILTER_IDX  0
#define CAPTURE_WRITE_TYPE_FILTER_IDX 1

// PROTOTYPES

statfunc bool filter_file_path(void *, void *, struct file *);
statfunc bool filter_file_type(void *, void *, size_t, struct file *, io_data_t, off_t);
statfunc bool filter_file_fd(void *, void *, size_t, struct file *);

// FUNCTIONS

// Return if the file does not match any given prefix filters in the filter map (so it should be
// filtered out). The result will be false if no filter exist.
statfunc bool filter_file_path(void *ctx, void *filter_map, struct file *file)
{
    path_buf_t *path_buf = get_path_str_cached(file);
    if (path_buf == NULL) {
        return false;
    }

    bool has_filter = false;
    bool filter_match = false;

// Check if the path matches filter prefixes
#pragma unroll
    for (int i = 0; i < 3; i++) {
        int idx = i;
        path_filter_t *filter_p = bpf_map_lookup_elem(filter_map, &idx);
        // Filter should be always initialized
        if (unlikely(filter_p == NULL)) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return false;
        }

        if (!filter_p->path[0])
            break;

        has_filter = true;

        if (has_prefix(filter_p->path, (char *) &path_buf->buf, MAX_PATH_PREF_SIZE)) {
            filter_match = true;
            break;
        }
    }

    return (has_filter && !filter_match);
}

// Return if the file does not match any given file type filters in the filter map (so it should be
// filtered out). The result will be false if no filter exist.
statfunc bool filter_file_type(void *ctx,
                               void *filter_map,
                               size_t map_idx,
                               struct file *file,
                               io_data_t io_data,
                               off_t start_pos)
{
    bool has_file_type = false;
    bool type_filter_match = false;

    file_type_t *ftype = bpf_map_lookup_elem(filter_map, &map_idx);
    // Filter should be always initialized
    if (unlikely(ftype == NULL)) {
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return false;
    }

    // Do check only if there is a filter
    if (*ftype != 0 && *ftype & FILTER_FILE_TYPE_MASK) {
        has_file_type = true;
        int imode_mode = get_inode_mode_from_file(file);
        if (*ftype & FILTER_PIPE_FILES) {
            struct pipe_inode_info *pipe = get_file_pipe_info(file);
            if (pipe != NULL) {
                type_filter_match = true;
                goto exit;
            }
        }
        if (*ftype & FILTER_SOCKET_FILES) {
            if (imode_mode & S_IFSOCK) {
                type_filter_match = true;
                goto exit;
            }
        }
        if (*ftype & FILTER_NORMAL_FILES) {
            if (imode_mode & S_IFREG) {
                type_filter_match = true;
                goto exit;
            }
        }
        if (*ftype & FILTER_ELF_FILES) {
            file_id_t file_id = get_file_id(file);
            file_id.ctime = 0;
            if (start_pos == 0) {
                // Check if header is matching ELF header
                u8 header[FILE_MAGIC_HDR_SIZE] = {};
                fill_file_header(header, io_data);
                if (header[0] == 0x7f && header[1] == 0x45 && header[2] == 0x4c &&
                    header[3] == 0x46) {
                    type_filter_match = true;
                    bpf_map_update_elem(&elf_files_map, &file_id, &type_filter_match, BPF_ANY);
                } else {
                    // Avoid considering the file ELF if further IO operation will occur
                    bpf_map_delete_elem(&elf_files_map, &file_id);
                }
            } else {
                // In the case of IO operation in chunks one after another, we want to check
                // if the file is already confirmed to be an ELF file in previous operation.
                bool *is_elf = bpf_map_lookup_elem(&elf_files_map, &file_id);
                if (is_elf != NULL && *is_elf == true) {
                    type_filter_match = true;
                }
            }
        }
    }

exit:
    return (has_file_type && !type_filter_match);
}

// Return if the file does not match any given file FD filters in the filter map (so it should be
// filtered out). The result will be false if no filter exist.
statfunc bool filter_file_fd(void *ctx, void *filter_map, size_t map_idx, struct file *file)
{
    bool has_fds_filter = false;
    bool fds_filter_match = false;

    file_type_t *fds_filter = bpf_map_lookup_elem(filter_map, &map_idx);
    // Filter should be always initialized
    if (unlikely(fds_filter == NULL)) {
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return false;
    }

    if (*fds_filter != 0 && *fds_filter & FILTER_FDS_MASK) {
        has_fds_filter = true;
        int standard_fds = get_standard_fds_from_struct_file(file);
#pragma unroll
        for (int fd = STDIN; fd <= STDERR; fd++) {
            bool is_fd = standard_fds & (1 << fd);
            int fd_filter = 1 << (fd + FILTER_FILE_FD_START_BIT);
            if ((*fds_filter & fd_filter) && is_fd) {
                fds_filter_match = true;
                break;
            }
        }
    }

    return (has_fds_filter && !fds_filter_match);
}

#endif