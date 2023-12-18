#ifndef __COMMON_FILESYSTEM_H__
#define __COMMON_FILESYSTEM_H__

#include <vmlinux.h>
#include <vmlinux_flavors.h>

#include <common/buffer.h>
#include <common/memory.h>
#include <common/consts.h>

// PROTOTYPES

statfunc u64 get_time_nanosec_timespec(struct timespec64 *);
statfunc u64 get_ctime_nanosec_from_inode(struct inode *);
statfunc struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *);
statfunc struct dentry *get_d_parent_ptr_from_dentry(struct dentry *);
statfunc struct qstr get_d_name_from_dentry(struct dentry *);
statfunc dev_t get_dev_from_file(struct file *);
statfunc unsigned long get_inode_nr_from_file(struct file *);
statfunc u64 get_ctime_nanosec_from_file(struct file *);
statfunc unsigned short get_inode_mode_from_file(struct file *);
statfunc struct path get_path_from_file(struct file *);
statfunc struct file *get_struct_file_from_fd(u64);
statfunc unsigned short get_inode_mode_from_fd(u64);
statfunc int check_fd_type(u64, u16);
statfunc unsigned long get_inode_nr_from_dentry(struct dentry *);
statfunc dev_t get_dev_from_dentry(struct dentry *);
statfunc u64 get_ctime_nanosec_from_dentry(struct dentry *);
statfunc size_t get_path_str_buf(struct path *, buf_t *);
statfunc void *get_path_str(struct path *);
statfunc file_id_t get_file_id(struct file *);
statfunc void *get_path_str_cached(struct file *);
statfunc void *get_dentry_path_str(struct dentry *);
statfunc file_info_t get_file_info(struct file *);
statfunc struct inode *get_inode_from_file(struct file *);
statfunc int get_standard_fds_from_struct_file(struct file *);
statfunc struct super_block *get_super_block_from_inode(struct inode *);
statfunc unsigned long get_s_magic_from_super_block(struct super_block *);
statfunc void fill_vfs_file_metadata(struct file *, u32, u8 *);
statfunc void fill_vfs_file_bin_args_io_data(io_data_t, bin_args_t *);
statfunc void fill_file_header(u8[FILE_MAGIC_HDR_SIZE], io_data_t);
statfunc void
fill_vfs_file_bin_args(u32, struct file *, loff_t *, io_data_t, size_t, int, bin_args_t *);

// FUNCTIONS

statfunc u64 get_time_nanosec_timespec(struct timespec64 *ts)
{
    time64_t sec = BPF_CORE_READ(ts, tv_sec);
    if (sec < 0)
        return 0;

    long ns = BPF_CORE_READ(ts, tv_nsec);

    return (sec * 1000000000L) + ns;
}

statfunc u64 get_ctime_nanosec_from_inode(struct inode *inode)
{
    struct timespec64 ts;
    if (bpf_core_field_exists(inode->__i_ctime)) { // Version >= 6.6
        ts = BPF_CORE_READ(inode, __i_ctime);
    } else {
        struct inode___older_v66 *old_inode = (void *) inode;
        ts = BPF_CORE_READ(old_inode, i_ctime);
    }
    return get_time_nanosec_timespec(&ts);
}

statfunc struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return BPF_CORE_READ(vfsmnt, mnt_root);
}

statfunc struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_parent);
}

statfunc struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_name);
}

statfunc dev_t get_dev_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

statfunc unsigned long get_inode_nr_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_ino);
}

statfunc u64 get_ctime_nanosec_from_file(struct file *file)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    return get_ctime_nanosec_from_inode(f_inode);
}

statfunc unsigned short get_inode_mode_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_mode);
}

statfunc struct path get_path_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_path);
}

statfunc struct file *get_struct_file_from_fd(u64 fd_num)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL)
        return NULL;

    struct file **files = BPF_CORE_READ(task, files, fdt, fd);
    if (files == NULL)
        return NULL;

    struct file *file;
    bpf_core_read(&file, sizeof(void *), &files[fd_num]);
    if (file == NULL)
        return NULL;

    return file;
}

statfunc unsigned short get_inode_mode_from_fd(u64 fd)
{
    struct file *f = get_struct_file_from_fd(fd);
    if (f == NULL) {
        return -1;
    }

    return BPF_CORE_READ(f, f_inode, i_mode);
}

statfunc int check_fd_type(u64 fd, u16 type)
{
    unsigned short i_mode = get_inode_mode_from_fd(fd);

    if ((i_mode & S_IFMT) == type) {
        return 1;
    }

    return 0;
}

statfunc unsigned long get_inode_nr_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_inode, i_ino);
}

statfunc dev_t get_dev_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
}

statfunc u64 get_ctime_nanosec_from_dentry(struct dentry *dentry)
{
    struct inode *d_inode = BPF_CORE_READ(dentry, d_inode);
    return get_ctime_nanosec_from_inode(d_inode);
}

// Read the file path to the given buffer, returning the start offset of the path.
statfunc size_t get_path_str_buf(struct path *path, buf_t *out_buf)
{
    if (path == NULL || out_buf == NULL) {
        return 0;
    }

    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;
    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;
        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                &(out_buf->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }
    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(out_buf->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(out_buf->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }
    return buf_off;
}

statfunc void *get_path_str(struct path *path)
{
    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

    size_t buf_off = get_path_str_buf(path, string_p);
    return &string_p->buf[buf_off];
}

statfunc file_id_t get_file_id(struct file *file)
{
    file_id_t file_id = {};
    if (file != NULL) {
        file_id.ctime = get_ctime_nanosec_from_file(file);
        file_id.device = get_dev_from_file(file);
        file_id.inode = get_inode_nr_from_file(file);
    }
    return file_id;
}

// get_path_str_cached - get the path of a specific file, using and updating cache map.
statfunc void *get_path_str_cached(struct file *file)
{
    file_id_t file_id = get_file_id(file);
    path_buf_t *path = bpf_map_lookup_elem(&io_file_path_cache_map, &file_id);
    if (path == NULL) {
        // Get per-cpu string buffer
        buf_t *string_p = get_buf(STRING_BUF_IDX);
        if (string_p == NULL)
            return NULL;

        size_t buf_off = get_path_str_buf(__builtin_preserve_access_index(&file->f_path), string_p);
        if (likely(sizeof(string_p->buf) > buf_off + sizeof(path_buf_t))) {
            path = (path_buf_t *) (&string_p->buf[0] + buf_off);
            bpf_map_update_elem(&io_file_path_cache_map, &file_id, path, BPF_ANY);
        } else {
            return NULL;
        }
    }
    return &path->buf;
}

statfunc void *get_dentry_path_str(struct dentry *dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    return &string_p->buf[buf_off];
}

statfunc file_info_t get_file_info(struct file *file)
{
    file_info_t file_info = {};
    if (file != NULL) {
        file_info.pathname_p = get_path_str(__builtin_preserve_access_index(&file->f_path));
        file_info.id = get_file_id(file);
    }
    return file_info;
}

statfunc struct inode *get_inode_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode);
}

// Return which of the standard FDs point to the given file as a bit field.
// The FDs matching bits are (1 << fd).
statfunc int get_standard_fds_from_struct_file(struct file *file)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL) {
        return -1;
    }
    struct files_struct *files = (struct files_struct *) BPF_CORE_READ(task, files);
    if (files == NULL) {
        return -2;
    }
    struct file **fd = (struct file **) BPF_CORE_READ(files, fdt, fd);
    if (fd == NULL) {
        return -3;
    }

    int fds = 0;
#pragma unroll
    for (int i = STDIN; i <= STDERR; i++) {
        struct file *fd_file = NULL;
        bpf_core_read(&fd_file, sizeof(struct file *), &fd[i]);
        if (fd_file == file) {
            fds |= 1 << i;
        }
    }

    return fds;
}

statfunc struct super_block *get_super_block_from_inode(struct inode *f_inode)
{
    return BPF_CORE_READ(f_inode, i_sb);
}

statfunc unsigned long get_s_magic_from_super_block(struct super_block *i_sb)
{
    return BPF_CORE_READ(i_sb, s_magic);
}

// INTERNAL: STRUCTS BUILDING
// -----------------------------------------------------------------------

statfunc void fill_vfs_file_metadata(struct file *file, u32 pid, u8 *metadata)
{
    // Extract device id, inode number and mode
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    unsigned short i_mode = get_inode_mode_from_file(file);

    bpf_probe_read(metadata, 4, &s_dev);
    bpf_probe_read(metadata + 4, 8, &inode_nr);
    bpf_probe_read(metadata + 12, 4, &i_mode);
    bpf_probe_read(metadata + 16, 4, &pid);
}

statfunc void fill_vfs_file_bin_args_io_data(io_data_t io_data, bin_args_t *bin_args)
{
    bin_args->ptr = io_data.ptr;
    bin_args->full_size = io_data.len;

    // handle case of write using iovec
    if (!io_data.is_buf && io_data.len > 0) {
        bin_args->vec = io_data.ptr;
        bin_args->iov_len = io_data.len;
        bin_args->iov_idx = 0;
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[0]);
        bin_args->ptr = io_vec.iov_base;
        bin_args->full_size = io_vec.iov_len;
    }
}

// Fill given bin_args_t argument with all needed information for vfs_file binary sending
statfunc void fill_vfs_file_bin_args(u32 type,
                                     struct file *file,
                                     loff_t *pos,
                                     io_data_t io_data,
                                     size_t write_bytes,
                                     int pid,
                                     bin_args_t *bin_args)
{
    off_t start_pos;

    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= write_bytes;

    bin_args->type = type;
    fill_vfs_file_metadata(file, pid, &bin_args->metadata[0]);
    bin_args->start_off = start_pos;
    fill_vfs_file_bin_args_io_data(io_data, bin_args);
}

statfunc void fill_file_header(u8 header[FILE_MAGIC_HDR_SIZE], io_data_t io_data)
{
    u32 len = (u32) io_data.len;
    if (io_data.is_buf) {
        // inline bounds check to force compiler to use the register of len
        asm volatile("if %[size] < %[max_size] goto +1;\n"
                     "%[size] = %[max_size];\n"
                     :
                     : [size] "r"(len), [max_size] "i"(FILE_MAGIC_HDR_SIZE));
        bpf_probe_read(header, len, io_data.ptr);
    } else {
        struct iovec io_vec;
        __builtin_memset(&io_vec, 0, sizeof(io_vec));
        bpf_probe_read(&io_vec, sizeof(struct iovec), io_data.ptr);
        // inline bounds check to force compiler to use the register of len
        asm volatile("if %[size] < %[max_size] goto +1;\n"
                     "%[size] = %[max_size];\n"
                     :
                     : [size] "r"(len), [max_size] "i"(FILE_MAGIC_HDR_SIZE));
        bpf_probe_read(header, len, io_vec.iov_base);
    }
}

#endif
