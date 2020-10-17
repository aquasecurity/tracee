// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/uio.h>
#include <uapi/linux/un.h>
#include <uapi/linux/utsname.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/version.h>

#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096          // Choosing this value to be the same as PATH_MAX
#define MAX_STR_ARR_ELEM    40            // String array elements number should be bounded due to instructions limit
#define MAX_PATH_PREF_SIZE  64            // Max path prefix should be bounded due to instructions limit

#define SUBMIT_BUF_IDX      0
#define STRING_BUF_IDX      1
#define FILE_BUF_IDX        2
#define MAX_BUFFERS         3

#define SEND_VFS_WRITE      1
#define SEND_MPROTECT       2
#define SEND_META_SIZE      20

#define ALERT_MMAP_W_X      1
#define ALERT_MPROT_X_ADD   2
#define ALERT_MPROT_W_ADD   3
#define ALERT_MPROT_W_REM   4

#define TAIL_VFS_WRITE      0
#define TAIL_VFS_WRITEV     1
#define TAIL_SEND_BIN       2
#define MAX_TAIL_CALL       3

#define NONE_T        0UL
#define INT_T         1UL
#define UINT_T        2UL
#define LONG_T        3UL
#define ULONG_T       4UL
#define OFF_T_T       5UL
#define MODE_T_T      6UL
#define DEV_T_T       7UL
#define SIZE_T_T      8UL
#define POINTER_T     9UL
#define STR_T         10UL
#define STR_ARR_T     11UL
#define SOCKADDR_T    12UL
#define ALERT_T       13UL
#define TYPE_MAX      255UL

#define TAG_NONE           0UL

#define SYS_OPEN            2
#define SYS_MMAP            9
#define SYS_MPROTECT        10
#define SYS_RT_SIGRETURN    15
#define SYS_CLONE           56
#define SYS_FORK            57
#define SYS_VFORK           58
#define SYS_EXECVE          59
#define SYS_EXIT            60
#define SYS_EXIT_GROUP      231
#define SYS_OPENAT          257
#define SYS_EXECVEAT        322
#define RAW_SYS_ENTER       335
#define RAW_SYS_EXIT        336
#define DO_EXIT             337
#define CAP_CAPABLE         338
#define SECURITY_BPRM_CHECK 339
#define SECURITY_FILE_OPEN  340
#define VFS_WRITE           341
#define VFS_WRITEV          342
#define MEM_PROT_ALERT      343
#define MAX_EVENT_ID        344

#define CONFIG_MODE             0
#define CONFIG_SHOW_SYSCALL     1
#define CONFIG_EXEC_ENV         2
#define CONFIG_CAPTURE_FILES    3
#define CONFIG_EXTRACT_DYN_CODE 4
#define CONFIG_TRACEE_PID       5

#define MODE_PROCESS_ALL        0
#define MODE_PROCESS_NEW        1
#define MODE_PROCESS_LIST       2
#define MODE_CONTAINER_NEW      3

// re-define container_of as bcc complains
#define my_container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) * __mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Minimal required kernel version is 4.14
#endif

/*=============================== INTERNAL STRUCTS ===========================*/

typedef struct context {
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 host_pid;               // PID in host pid namespace
    u32 host_tid;               // TID in host pid namespace
    u32 host_ppid;              // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 eventid;
    s64 retval;
    u8 argnum;
} context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct bin_args {
    u8 type;
    u8 metadata[SEND_META_SIZE];
    char *ptr;
    loff_t start_off;
    unsigned int full_size;
    u8 iov_idx;
    u8 iov_len;
    struct iovec *vec;
} bin_args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef struct path_filter {
    char path[MAX_PATH_PREF_SIZE];
} path_filter_t;

typedef struct alert {
    u64 ts;     // Timestamp
    u32 msg;    // Encoded message
    u8 payload; // Non zero if payload is sent to userspace
} alert_t;

/*================================ KERNEL STRUCTS =============================*/

struct mnt_namespace {
    atomic_t        count;
    struct ns_common    ns;
    // ...
};

struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
    // ...
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

/*=================================== MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                     // Various configurations
BPF_HASH(chosen_events_map, u32, u32);              // Various configurations
BPF_HASH(pids_map, u32, u32);                       // Save container pid namespaces
BPF_HASH(args_map, u64, args_t);                    // Persist args info between function entry and return
BPF_HASH(ret_map, u64, u64);                        // Persist return value to be used in tail calls
BPF_HASH(bin_args_map, u64, bin_args_t);            // Persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32);               // Map 32bit syscalls numbers to 64bit syscalls numbers
BPF_HASH(params_types_map, u32, u64);               // Encoded parameters types for event
BPF_HASH(params_names_map, u32, u64);               // Encoded parameters names for event
BPF_ARRAY(file_filter, path_filter_t, 3);           // Used to filter vfs_write events
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);         // Percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);       // Holds offsets to bufs respectively
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);          // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);      // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);       // Used to store programs for tail calls

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                            // Events submission
BPF_PERF_OUTPUT(file_writes);                       // File writes events submission

/*================== KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->mnt_ns)->ns.inum);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->ns.inum);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->level);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(task->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards:
    return READ_KERN(READ_KERN(task->thread_pid)->numbers[level].nr);
#endif
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(group_leader->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards:
    return READ_KERN(READ_KERN(group_leader->thread_pid)->numbers[level].nr);
#endif
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(real_parent->nsproxy)->pid_ns_for_children)->level);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(real_parent->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards:
    return READ_KERN(READ_KERN(real_parent->thread_pid)->numbers[level].nr);
#endif
}

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->uts_ns)->name.nodename);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    return READ_KERN(READ_KERN(task->real_parent)->pid);
}

static __always_inline bool is_x86_compat(struct task_struct *task)
{
    return READ_KERN(task->thread_info.status) & TS_COMPAT;
}

static __always_inline struct pt_regs* get_task_pt_regs(struct task_struct *task)
{
    void* __ptr = READ_KERN(task->stack) + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *)__ptr) - 1;
}

static __always_inline int get_syscall_ev_id_from_regs()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pt_regs *real_ctx = get_task_pt_regs(task);
    int syscall_nr = READ_KERN(real_ctx->orig_ax);

    if (is_x86_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls (which also represent the event ids)
        u32 *id_64 = sys_32_to_64_map.lookup(&syscall_nr);
        if (id_64 == 0)
            return -1;

        syscall_nr = *id_64;
    }

    return syscall_nr;
}

static __always_inline struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline struct file* get_file_ptr_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->file);
}

static __always_inline dev_t get_dev_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(READ_KERN(file->f_inode)->i_sb)->s_dev);
}

static __always_inline unsigned long get_inode_nr_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(file->f_inode)->i_ino);
}

static __always_inline unsigned short get_inode_mode_from_file(struct file *file)
{
    return READ_KERN(READ_KERN(file->f_inode)->i_mode);
}

static __always_inline struct path get_path_from_file(struct file *file)
{
    return READ_KERN(file->f_path);
}

static __always_inline unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return READ_KERN(vma->vm_flags);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return my_container_of(mnt, struct mount, mnt);
}

/*============================== HELPER FUNCTIONS ==============================*/

static __inline int is_prefix(char *prefix, char *str)
{
    int i;
    #pragma unroll
    for (i = 0; i < MAX_PATH_PREF_SIZE; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    // prefix is too long
    return 0;
}

static __always_inline u32 lookup_pid()
{
    u32 pid = bpf_get_current_pid_tgid();
    if (pids_map.lookup(&pid) == 0)
        return 0;

    return pid;
}

static __always_inline u32 lookup_pid_ns(struct task_struct *task)
{
    u32 task_pid_ns = get_task_pid_ns_id(task);

    u32 *pid_ns = pids_map.lookup(&task_pid_ns);
    if (pid_ns == 0)
        return 0;

    return *pid_ns;
}

static __always_inline void add_pid_fork(u32 pid)
{
    pids_map.update(&pid, &pid);
}

static __always_inline u32 add_pid()
{
    u32 pid = bpf_get_current_pid_tgid();
    if (pids_map.lookup(&pid) == 0)
        pids_map.update(&pid, &pid);

    return pid;
}

static __always_inline u32 add_pid_ns_if_needed()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pids_map.lookup(&pid_ns) != 0)
        // Container pidns was already added to map
        return pid_ns;

    // If pid equals 1 - start tracing the container
    if (get_task_ns_pid(task) == 1) {
        // A new container/pod was started - add pid namespace to map
        pids_map.update(&pid_ns, &pid_ns);
        return pid_ns;
    }

    // Not a container/pod
    return 0;
}

static __always_inline void remove_pid()
{
    u32 pid = bpf_get_current_pid_tgid();
    if (pids_map.lookup(&pid) != 0)
        pids_map.delete(&pid);
}

static __always_inline void remove_pid_ns_if_needed()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pids_map.lookup(&pid_ns) != 0) {
        // If pid equals 1 - stop tracing this pid namespace
        if (get_task_ns_pid(task) == 1) {
            pids_map.delete(&pid_ns);
        }
    }
}

static __always_inline int get_config(u32 key)
{
    u32 *config = config_map.lookup(&key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int should_trace()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int config_mode = get_config(CONFIG_MODE);
    u32 rc = 0;

    if (get_config(CONFIG_TRACEE_PID) == bpf_get_current_pid_tgid() >> 32)
        return 0;

    // All logs all processes except tracee itself
    if (config_mode == MODE_PROCESS_ALL)
        return 1;
    else if (config_mode == MODE_CONTAINER_NEW)
        rc = lookup_pid_ns(task);
    else if (config_mode == MODE_PROCESS_NEW || config_mode == MODE_PROCESS_LIST)
        rc = lookup_pid();

    return rc;
}

static __always_inline int event_chosen(u32 key)
{
    u32 *config = chosen_events_map.lookup(&key);
    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->host_ppid = get_task_ppid(task);
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char * uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);

    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns()/1000;

    return 0;
}

static __always_inline buf_t* get_buf(int idx)
{
    return bufs.lookup(&idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bufs_off.update(&buf_idx, &new_off);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bufs_off.lookup(&buf_idx);
}

// Context will always be at the start of the submission buffer
// It may be needed to resave the context if the arguments number changed by logic
static __always_inline int save_context_to_buf(buf_t *submit_p, void *ptr)
{
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static __always_inline context_t init_and_save_context(buf_t *submit_p, u32 id, u8 argnum, long ret)
{
    context_t context = {};
    init_context(&context);
    context.eventid = id;
    context.argnum = argnum;
    context.retval = ret;
    save_context_to_buf(submit_p, (void*)&context);

    return context;
}

static __always_inline int save_to_submit_buf(buf_t *submit_p, void *ptr, u32 size, u8 type, u8 tag)
{
// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
    if (type == 0)
        return 0;

    if (size == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument type
    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    // Save argument tag
    if (tag != TAG_NONE) {
        rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
        if (rc != 0) {
            *off -= 1;
            return 0;
        }

        *off += 1;
    }
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        return 1;
    }

    *off -= 2;
    return 0;
}

static __always_inline int save_str_to_buf(buf_t *submit_p, void *ptr, u8 tag)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);

    *off += 1;

    // Save argument tag
    if (tag != TAG_NONE) {
        int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
        if (rc != 0) {
            *off -= 1;
            return 0;
        }

        *off += 1;
    }

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int)) {
            // Satisfy validator for probe read
            *off -= 2;
            return 0;
        }
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        return 1;
    }

    *off -= 2;
    return 0;
}

static __always_inline int save_str_arr_to_buf(buf_t *submit_p, const char __user *const __user *ptr, u8 tag)
{
    u8 elem_num = 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // mark string array start
    u8 type = STR_ARR_T;
    int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }

    *off += 1;

    // Save space for number of elements
    u32 orig_off = *off;
    *off += 1;

    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator for probe read
                goto out;
            bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
            *off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator for probe read
            goto out;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    bpf_probe_read(&(submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &elem_num);
    return 1;
}

static __always_inline int save_file_path_to_str_buf(buf_t *string_p, struct file* file)
{
    struct path f_path = get_path_from_file(file);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_p = real_mount(vfsmnt);
    struct mount mnt;
    bpf_probe_read(&mnt, sizeof(struct mount), mnt_p);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    #pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 30; i++) {
        struct dentry *mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        struct dentry *d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt.mnt_parent) {
                // We reached root, but not global root - continue with mount point path
                dentry = mnt.mnt_mountpoint;
                bpf_probe_read(&mnt, sizeof(struct mount), mnt.mnt_parent);
                vfsmnt = &mnt.mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
            sz = bpf_probe_read_str(&(string_p->buf[off]), len, (void *)d_name.name);
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE) {
	// memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        int sz = bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return buf_off;
}

static __always_inline int events_perf_submit(void *ctx)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = *off & (MAX_PERCPU_BUFSIZE-1);
    void * data = submit_p->buf;
    return events.perf_submit(ctx, data, size);
}

static __always_inline int is_container()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    return lookup_pid_ns(task);
}

static __always_inline int save_args(args_t *args, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    args_map.update(&id, args);

    return 0;
}

static __always_inline int save_args_from_regs(struct pt_regs *ctx, u32 event_id, bool is_syscall)
{
    args_t args = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_x86_compat(task) && is_syscall) {
        args.args[0] = ctx->bx;
        args.args[1] = ctx->cx;
        args.args[2] = ctx->dx;
        args.args[3] = ctx->si;
        args.args[4] = ctx->di;
        args.args[5] = ctx->bp;
    } else {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    }

    return save_args(&args, event_id);
}

static __always_inline int load_args(args_t *args, bool delete, u32 event_id)
{
    args_t *saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = args_map.lookup(&id);
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

    if (delete)
        args_map.delete(&id);

    return 0;
}

static __always_inline int del_args(u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    args_map.delete(&id);

    return 0;
}

static __always_inline int save_retval(u64 retval, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    ret_map.update(&id, &retval);

    return 0;
}

static __always_inline int load_retval(u64 *retval, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    u64 *saved_retval = ret_map.lookup(&id);
    if (saved_retval == 0) {
        // missed entry or not traced
        return -1;
    }

    *retval = *saved_retval;
    ret_map.delete(&id);

    return 0;
}

static __always_inline int del_retval(u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    ret_map.delete(&id);

    return 0;
}

#define DEC_ARG(n, enc_arg) ((enc_arg>>(8*n))&0xFF)

static __always_inline int save_args_to_submit_buf(u64 types, u64 tags, args_t *args)
{
    unsigned int i;
    unsigned int rc = 0;
    unsigned int arg_num = 0;
    short family = 0;

    if (types == 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    #pragma unroll
    for(i=0; i<6; i++)
    {
        int size = 0;
        u8 type = DEC_ARG(i, types);
        u8 tag = DEC_ARG(i, tags);
        switch (type)
        {
            case NONE_T:
                break;
            case INT_T:
                size = sizeof(int);
                break;
            case UINT_T:
                size = sizeof(unsigned int);
                break;
            case OFF_T_T:
                size = sizeof(off_t);
                break;
            case DEV_T_T:
                size = sizeof(dev_t);
                break;
            case MODE_T_T:
                size = sizeof(mode_t);
                break;
            case LONG_T:
                size = sizeof(long);
                break;
            case ULONG_T:
                size = sizeof(unsigned long);
                break;
            case SIZE_T_T:
                size = sizeof(size_t);
                break;
            case POINTER_T:
                size = sizeof(void*);
                break;
            case STR_T:
                rc = save_str_to_buf(submit_p, (void *)args->args[i], tag);
                break;
            case SOCKADDR_T:
                if (args->args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void*)args->args[i]);
                    switch (family)
                    {
                        case AF_UNIX:
                            size = sizeof(struct sockaddr_un);
                            break;
                        case AF_INET:
                            size = sizeof(struct sockaddr_in);
                            break;
                        case AF_INET6:
                            size = sizeof(struct sockaddr_in6);
                            break;
                        default:
                            size = sizeof(short);
                    }
                    rc = save_to_submit_buf(submit_p, (void*)(args->args[i]), size, type, tag);
                } else {
                    rc = save_to_submit_buf(submit_p, &family, sizeof(short), type, tag);
                }
                break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T))
            rc = save_to_submit_buf(submit_p, (void*)&(args->args[i]), size, type, tag);

        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

static __always_inline int trace_ret_generic(void *ctx, u32 id, u64 types, u64 tags, args_t *args, long ret)
{
    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    u8 argnum = save_args_to_submit_buf(types, tags, args);
    init_and_save_context(submit_p, id, argnum, ret);

    events_perf_submit(ctx);
    return 0;
}

#define TRACE_ENT_FUNC(name, id)                                        \
int trace_##name(void *ctx)                                             \
{                                                                       \
    if (!should_trace())                                                \
        return 0;                                                       \
    return save_args_from_regs(ctx, id, false);                         \
}

#define TRACE_RET_FUNC(name, id, types, tags, ret)                      \
int trace_ret_##name(void *ctx)                                         \
{                                                                       \
    args_t args = {};                                                   \
                                                                        \
    bool delete_args = true;                                            \
    if (load_args(&args, delete_args, id) != 0)                         \
        return -1;                                                      \
                                                                        \
    if (!should_trace())                                                \
        return -1;                                                      \
                                                                        \
    if (!event_chosen(id))                                              \
        return 0;                                                       \
                                                                        \
    return trace_ret_generic(ctx, id, types, tags, &args, ret);         \
}

/*============================== SYSCALL HOOKS ==============================*/

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long id)
int tracepoint__raw_syscalls__sys_enter(
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
struct tracepoint__raw_syscalls__sys_enter *args
#else
struct bpf_raw_tracepoint_args *ctx
#endif
)
{
    struct pt_regs regs = {};
    int id;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    void *ctx = args;
    if (!is_x86_compat(task)) {
        regs.di = args->args[0];
        regs.si = args->args[1];
        regs.dx = args->args[2];
        regs.r10 = args->args[3];
        regs.r8 = args->args[4];
        regs.r9 = args->args[5];
    } else {
        regs.bx = args->args[0];
        regs.cx = args->args[1];
        regs.dx = args->args[2];
        regs.si = args->args[3];
        regs.di = args->args[4];
        regs.bp = args->args[5];
    }
    id = args->id;
#else
    bpf_probe_read(&regs, sizeof(struct pt_regs), (void*)ctx->args[0]);
    id = ctx->args[1];
#endif

    if (is_x86_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32 *id_64 = sys_32_to_64_map.lookup(&id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // execve events may add new pids to the traced pids set
    // perform this check before should_trace() so newly executed binaries will be traced
    if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
        int config_mode = get_config(CONFIG_MODE);
        if (config_mode == MODE_CONTAINER_NEW) {
            add_pid_ns_if_needed();
        } else if (config_mode == MODE_PROCESS_NEW || config_mode == MODE_PROCESS_ALL) {
            add_pid();
        }
    }

    if (!should_trace())
        return 0;

    if (event_chosen(RAW_SYS_ENTER)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(submit_p, RAW_SYS_ENTER, 1 /*argnum*/, 0 /*ret*/);

        u64 *tags = params_names_map.lookup(&context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_submit_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    // exit, exit_group and rt_sigreturn syscalls don't return - don't save args for them
    if (id != SYS_EXIT && id != SYS_EXIT_GROUP && id != SYS_RT_SIGRETURN) {
        save_args_from_regs(&regs, id, true);
    }

    // call syscall handler, if exists
    // enter tail calls should never delete saved args
    sys_enter_tails.call(ctx, id);
    return 0;
}

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long ret)
int tracepoint__raw_syscalls__sys_exit(
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
struct tracepoint__raw_syscalls__sys_exit *args
#else
struct bpf_raw_tracepoint_args *ctx
#endif
)
{
    int id;
    long ret;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    void *ctx = args;
    id = args->id;
    ret = args->ret;
#else
    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
    id = regs->orig_ax;
    ret = ctx->args[1];
#endif

    if (is_x86_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32 *id_64 = sys_32_to_64_map.lookup(&id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    args_t saved_args = {};
    bool delete_args = true;
    if (load_args(&saved_args, delete_args, id) != 0)
        return 0;

    if (!should_trace())
        return 0;

    // TODO PATH
    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    if (id == SYS_CLONE || id == SYS_FORK || id == SYS_VFORK) {
        if (get_config(CONFIG_MODE) != MODE_CONTAINER_NEW) {
            u32 pid = ret;
            add_pid_fork(pid);
        }
    }

    if (event_chosen(RAW_SYS_EXIT)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(submit_p, RAW_SYS_EXIT, 1 /*argnum*/, ret);

        u64 *tags = params_names_map.lookup(&context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_submit_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    if (event_chosen(id)) {
        u64 types = 0;
        u64 tags = 0;
        bool submit_event = true;
        if (id != SYS_EXECVE && id != SYS_EXECVEAT) {
            u64 *saved_types = params_types_map.lookup(&id);
            u64 *saved_tags = params_names_map.lookup(&id);
            if (!saved_types || !saved_tags) {
                return -1;
            }
            types = *saved_types;
            tags = *saved_tags;
        } else {
            // We can't use saved args after execve syscall, as pointers are invalid
            // To avoid showing execve event both on entry and exit,
            // we only output failed execs
            if (ret == 0)
                submit_event = false;
        }

        if (submit_event)
            trace_ret_generic(ctx, id, types, tags, &saved_args, ret);
    }

    // call syscall handler, if exists
    save_args(&saved_args, id);
    save_retval(ret, id);
    // exit tail calls should always delete args and retval before return
    sys_exit_tails.call(ctx, id);
    del_retval(id);
    del_args(id);
    return 0;
}

int syscall__execve(void *ctx)
{
    args_t args = {};

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVE) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVE))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, SYS_EXECVE, 2 /*argnum*/, 0 /*ret*/);

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)args.args[0] /*filename*/, DEC_ARG(0, *tags));
    save_str_arr_to_buf(submit_p, (const char *const *)args.args[1] /*argv*/, DEC_ARG(1, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        context.argnum++;
        save_context_to_buf(submit_p, (void*)&context);
        save_str_arr_to_buf(submit_p, (const char *const *)args.args[2] /*envp*/, DEC_ARG(2, *tags));
    }

    events_perf_submit(ctx);
    return 0;
}

int syscall__execveat(void *ctx)
{
    args_t args = {};

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVEAT) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVEAT))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, SYS_EXECVEAT, 4 /*argnum*/, 0 /*ret*/);

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void*)&args.args[0] /*dirfd*/, sizeof(int), INT_T, DEC_ARG(0, *tags));
    save_str_to_buf(submit_p, (void *)args.args[1] /*pathname*/, DEC_ARG(1, *tags));
    save_str_arr_to_buf(submit_p, (const char *const *)args.args[2] /*argv*/, DEC_ARG(2, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        context.argnum++;
        save_context_to_buf(submit_p, (void*)&context);
        save_str_arr_to_buf(submit_p, (const char *const *)args.args[3] /*envp*/, DEC_ARG(3, *tags));
    }
    save_to_submit_buf(submit_p, (void*)&args.args[4] /*flags*/, sizeof(int), INT_T, DEC_ARG(4, *tags));

    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

int trace_do_exit(struct pt_regs *ctx, long code)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    init_and_save_context(submit_p, DO_EXIT, 0, code);

    if (get_config(CONFIG_MODE) == MODE_CONTAINER_NEW)
        remove_pid_ns_if_needed();
    else
        remove_pid();

    events_perf_submit(ctx);
    return 0;
}

int trace_security_bprm_check(struct pt_regs *ctx, struct linux_binprm *bprm)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, SECURITY_BPRM_CHECK, 3 /*argnum*/, 0 /*ret*/);

    struct file* file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(2, *tags));

    events_perf_submit(ctx);
    return 0;
}

int trace_security_file_open(struct pt_regs *ctx, struct file *file)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, SECURITY_FILE_OPEN, 4 /*argnum*/, 0 /*ret*/);

    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);

    // only monitor open and openat syscalls
    int syscall_nr = get_syscall_ev_id_from_regs();
    if (syscall_nr != SYS_OPEN && syscall_nr != SYS_OPENAT)
        return 0;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, (void*)&file->f_flags, sizeof(int), INT_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(2, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));

    events_perf_submit(ctx);
    return 0;
}

int trace_cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int cap_opt)
{
    int audit;

    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, CAP_CAPABLE, 1 /*argnum*/, 0 /*ret*/);

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void*)&cap, sizeof(int), INT_T, DEC_ARG(0, *tags));
    if (get_config(CONFIG_SHOW_SYSCALL)) {
        int syscall_nr = get_syscall_ev_id_from_regs();
        if (syscall_nr >= 0) {
            context.argnum++;
            save_context_to_buf(submit_p, (void*)&context);
            save_to_submit_buf(submit_p, (void*)&syscall_nr, sizeof(int), INT_T, DEC_ARG(1, *tags));
        }
    }
    events_perf_submit(ctx);
    return 0;
};

int send_bin(struct pt_regs *ctx)
{
    // Note: sending the data to the userspace have the following constraints:
    // 1. We need a buffer that we know it's exact size (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data can be overriden if userspace doesn't consume it fast enough

    int i = 0;
    unsigned int chunk_size;

    u64 id = bpf_get_current_pid_tgid();

    bin_args_t *bin_args = bin_args_map.lookup(&id);
    if (bin_args == 0) {
        // missed entry or not traced
        return 0;
    }

    if (bin_args->full_size <= 0) {
        // If there are more vector elements, continue to the next one
        bin_args->iov_idx++;
        if (bin_args->iov_idx < bin_args->iov_len) {
            // Handle the rest of the write recursively
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
            bin_args->ptr = io_vec.iov_base;
            bin_args->full_size = io_vec.iov_len;
            prog_array.call(ctx, TAIL_SEND_BIN);
        }
        bin_args_map.delete(&id);
        return 0;
    }

    buf_t *file_buf_p = get_buf(FILE_BUF_IDX);
    if (file_buf_p == NULL) {
        bin_args_map.delete(&id);
        return 0;
    }

#define F_SEND_TYPE   0
#define F_MNT_NS      (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF    (F_MNT_NS + sizeof(u32))
#define F_SZ_OFF      (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF     (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF   (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE  (MAX_PERCPU_BUFSIZE - F_CHUNK_OFF - 4)

    bpf_probe_read((void **)&(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args->type);

    u32 mnt_id = get_task_mnt_ns_id((struct task_struct *)bpf_get_current_task());
    bpf_probe_read((void **)&(file_buf_p->buf[F_MNT_NS]), sizeof(u32), &mnt_id);

    // Save metadata to be used in filename
    bpf_probe_read((void **)&(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args->metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = bin_args->full_size/F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

    // Handle full chunks in loop
    #pragma unroll
    for (i = 0; i < 110; i++) {
        // Dummy instruction, as break instruction can't be first with unroll optimization
        chunk_size = F_CHUNK_SIZE;

        if (i == full_chunk_num)
            break;

        // Save binary chunk and file position of write
        bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);
        bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, bin_args->ptr);
        bin_args->ptr += F_CHUNK_SIZE;
        bin_args->start_off += F_CHUNK_SIZE;

        file_writes.perf_submit(ctx, data, F_CHUNK_OFF+F_CHUNK_SIZE);
    }

    chunk_size = bin_args->full_size - i*F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        // Handle the rest of the write recursively
        bin_args->full_size = chunk_size;
        prog_array.call(ctx, TAIL_SEND_BIN);
        bin_args_map.delete(&id);
        return 0;
    }

    // Save last chunk
    bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
    bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

    // Satisfy validator by setting buffer bounds
    int size = (F_CHUNK_OFF+chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
    file_writes.perf_submit(ctx, data, size);

    // We finished writing an element of the vector - continue to next element
    bin_args->iov_idx++;
    if (bin_args->iov_idx < bin_args->iov_len) {
        // Handle the rest of the write recursively
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
        bin_args->ptr = io_vec.iov_base;
        bin_args->full_size = io_vec.iov_len;
        prog_array.call(ctx, TAIL_SEND_BIN);
    }

    bin_args_map.delete(&id);
    return 0;
}

static __always_inline int do_vfs_write_writev(struct pt_regs *ctx, u32 event_id, u32 tail_call_id)
{
    args_t saved_args;
    bool has_filter = false;

    bool delete_args = false;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    struct file *file      = (struct file *) saved_args.args[0];

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    #pragma unroll
    for (int i = 0; i < 3; i++) {
        int idx = i;
        path_filter_t *filter_p = file_filter.lookup(&idx);
        if (filter_p == NULL)
            return -1;

        if (!filter_p->path[0])
            break;

        has_filter = true;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
            break;

        if (filter_p->path[0] && is_prefix(filter_p->path, &string_p->buf[*off]))
            prog_array.call(ctx, tail_call_id);
    }

    if (has_filter) {
        // There is a filter, but no match
        del_args(event_id);
        return 0;
    }

    // No filter was given - continue
    prog_array.call(ctx, tail_call_id);
    return 0;
}

static __always_inline int do_vfs_write_writev_tail(struct pt_regs *ctx, u32 event_id)
{
    args_t saved_args;
    bin_args_t bin_args = {};
    loff_t start_pos;

    void *ptr;
    size_t count;
    struct iovec *vec;
    unsigned long vlen;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, event_id, 5 /*argnum*/, PT_REGS_RC(ctx));

    bool delete_args = true;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    struct file *file      = (struct file *) saved_args.args[0];
    if (event_id == VFS_WRITE) {
        ptr                = (void*)         saved_args.args[1];
        count              = (size_t)        saved_args.args[2];
    } else {
        vec                = (struct iovec*) saved_args.args[1];
        vlen               =                 saved_args.args[2];
    }
    loff_t *pos            = (loff_t*)       saved_args.args[3];

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    // Extract device id, inode number, mode, and pos (offset)
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    unsigned short i_mode = get_inode_mode_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= PT_REGS_RC(ctx);

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(2, *tags));
    if (event_id == VFS_WRITE)
        save_to_submit_buf(submit_p, &count, sizeof(size_t), SIZE_T_T, DEC_ARG(3, *tags));
    else
        save_to_submit_buf(submit_p, &vlen, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));
    save_to_submit_buf(submit_p, &start_pos, sizeof(off_t), OFF_T_T, DEC_ARG(4, *tags));

    // Submit vfs_write(v) event
    events_perf_submit(ctx);

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = context.pid;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
        return -1;
    if (!is_prefix("/dev/null", &string_p->buf[*off]))
        pid = 0;

    if (get_config(CONFIG_CAPTURE_FILES)) {
        bin_args.type = SEND_VFS_WRITE;
        bpf_probe_read(bin_args.metadata, 4, &s_dev);
        bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
        bpf_probe_read(&bin_args.metadata[12], 4, &i_mode);
        bpf_probe_read(&bin_args.metadata[16], 4, &pid);
        bin_args.start_off = start_pos;
        if (event_id == VFS_WRITE) {
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
        bin_args_map.update(&id, &bin_args);

        // Send file data
        prog_array.call(ctx, TAIL_SEND_BIN);
    }
    return 0;
}

TRACE_ENT_FUNC(vfs_write, VFS_WRITE);

int trace_ret_vfs_write(struct pt_regs *ctx)
{
    return do_vfs_write_writev(ctx, VFS_WRITE, TAIL_VFS_WRITE);
}

int trace_ret_vfs_write_tail(struct pt_regs *ctx)
{
    return do_vfs_write_writev_tail(ctx, VFS_WRITE);
}

TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

int trace_ret_vfs_writev(struct pt_regs *ctx)
{
    return do_vfs_write_writev(ctx, VFS_WRITEV, TAIL_VFS_WRITEV);
}

int trace_ret_vfs_writev_tail(struct pt_regs *ctx)
{
    return do_vfs_write_writev_tail(ctx, VFS_WRITEV);
}

int trace_mmap_alert(struct pt_regs *ctx)
{
    args_t args = {};

    // Arguments will be deleted on raw_syscalls_exit (with mmap syscall id)
    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_MMAP) != 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, MEM_PROT_ALERT, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    if ((args.args[2] & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC)) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MMAP_W_X, .payload = 0};
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    return 0;
}

int trace_mprotect_alert(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    args_t args = {};
    bin_args_t bin_args = {};

    // Arguments will be deleted on raw_syscalls_exit (with mprotect syscall id)
    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_MPROTECT) != 0)
        return 0;

    void *addr = (void*)args.args[0];
    size_t len = args.args[1];
    unsigned long prev_prot = get_vma_flags(vma);

    if (addr <= 0)
        return 0;

    // If length is 0, the current page permissions are changed
    if (len == 0)
        len = PAGE_SIZE;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(submit_p, MEM_PROT_ALERT, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = params_names_map.lookup(&context.eventid);
    if (!tags) {
        return -1;
    }

    if ((!(prev_prot & VM_EXEC)) && (reqprot & VM_EXEC)) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MPROT_X_ADD, .payload = 0};
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
        return 0;
    }

    if ((prev_prot & VM_EXEC) && !(prev_prot & VM_WRITE)
        && ((reqprot & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC))) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MPROT_W_ADD, .payload = 0};
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
        return 0;
    }

    if (((prev_prot & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC))
        && (reqprot & VM_EXEC) && !(reqprot & VM_WRITE)) {
        alert_t alert = {.ts = context.ts, .msg = ALERT_MPROT_W_REM, .payload = 0 };
        if (get_config(CONFIG_EXTRACT_DYN_CODE)) 
            alert.payload = 1;
        save_to_submit_buf(submit_p, &alert, sizeof(alert_t), ALERT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);

        if (get_config(CONFIG_EXTRACT_DYN_CODE)) {
            bin_args.type = SEND_MPROTECT;
            bpf_probe_read(bin_args.metadata, sizeof(u64), &context.ts);
            bin_args.ptr = (char *)addr;
            bin_args.start_off = 0;
            bin_args.full_size = len;

            u64 id = bpf_get_current_pid_tgid();
            bin_args_map.update(&id, &bin_args);
            prog_array.call(ctx, TAIL_SEND_BIN);
        }
    }

    return 0;
}
