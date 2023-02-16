#ifndef __TRACEE_FILESYSTEM_H__
#define __TRACEE_FILESYSTEM_H__

#ifndef CORE
    #include <missing_noncore_definitions.h>
#else
    #include <missing_definitions.h>
    #include <vmlinux.h>
#endif

#include <bpf/bpf_helpers.h>
#include "common/buffer.h"
#include "common/common.h"
#include "consts.h"
#include "memory.h"
#include "maps.h"

static __always_inline u64 get_ctime_nanosec_from_inode(struct inode *inode)
{
    struct timespec64 ts = READ_KERN(inode->i_ctime);
    time64_t sec = READ_KERN(ts.tv_sec);
    if (sec < 0)
        return 0;
    long ns = READ_KERN(ts.tv_nsec);
    return (sec * 1000000000L) + ns;
}

static __always_inline struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline dev_t get_dev_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    struct super_block *i_sb = READ_KERN(f_inode->i_sb);
    return READ_KERN(i_sb->s_dev);
}

static __always_inline unsigned long get_inode_nr_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    return READ_KERN(f_inode->i_ino);
}

static __always_inline u64 get_ctime_nanosec_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    return get_ctime_nanosec_from_inode(f_inode);
}

static __always_inline unsigned short get_inode_mode_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    return READ_KERN(f_inode->i_mode);
}

static __always_inline struct path get_path_from_file(struct file *file)
{
    return READ_KERN(file->f_path);
}

static __always_inline struct file *get_struct_file_from_fd(u64 fd_num)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL) {
        return NULL;
    }
    struct files_struct *files = (struct files_struct *) READ_KERN(task->files);
    if (files == NULL) {
        return NULL;
    }
    struct fdtable *fdt = (struct fdtable *) READ_KERN(files->fdt);
    if (fdt == NULL) {
        return NULL;
    }
    struct file **fd = (struct file **) READ_KERN(fdt->fd);
    if (fd == NULL) {
        return NULL;
    }
    struct file *f = (struct file *) READ_KERN(fd[fd_num]);
    if (f == NULL) {
        return NULL;
    }

    return f;
}

static __always_inline unsigned short get_inode_mode_from_fd(u64 fd)
{
    struct file *f = get_struct_file_from_fd(fd);
    if (f == NULL) {
        return -1;
    }

    struct inode *f_inode = READ_KERN(f->f_inode);
    return READ_KERN(f_inode->i_mode);
}

static __always_inline int check_fd_type(u64 fd, u16 type)
{
    unsigned short i_mode = get_inode_mode_from_fd(fd);

    if ((i_mode & S_IFMT) == type) {
        return 1;
    }

    return 0;
}

static __always_inline unsigned long get_inode_nr_from_dentry(struct dentry *dentry)
{
    struct inode *d_inode = READ_KERN(dentry->d_inode);
    return READ_KERN(d_inode->i_ino);
}

static __always_inline dev_t get_dev_from_dentry(struct dentry *dentry)
{
    struct inode *d_inode = READ_KERN(dentry->d_inode);
    struct super_block *i_sb = READ_KERN(d_inode->i_sb);
    return READ_KERN(i_sb->s_dev);
}

static __always_inline u64 get_ctime_nanosec_from_dentry(struct dentry *dentry)
{
    struct inode *d_inode = READ_KERN(dentry->d_inode);
    return get_ctime_nanosec_from_inode(d_inode);
}

static __always_inline void *get_path_str(struct path *path)
{
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

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

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
        d_name = get_d_name_from_dentry(dentry);
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

static __always_inline void *get_dentry_path_str(struct dentry *dentry)
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

static __always_inline file_info_t get_file_info(struct file *file)
{
    file_info_t file_info = {};
    if (file != NULL) {
        file_info.pathname_p = get_path_str(GET_FIELD_ADDR(file->f_path));
        file_info.ctime = get_ctime_nanosec_from_file(file);
        file_info.device = get_dev_from_file(file);
        file_info.inode = get_inode_nr_from_file(file);
    }
    return file_info;
}

static __always_inline struct inode *get_inode_from_file(struct file *file)
{
    return READ_KERN(file->f_inode);
}

static __always_inline struct super_block *get_super_block_from_inode(struct inode *f_inode)
{
    return READ_KERN(f_inode->i_sb);
}

static __always_inline unsigned long get_s_magic_from_super_block(struct super_block *i_sb)
{
    return READ_KERN(i_sb->s_magic);
}

#endif