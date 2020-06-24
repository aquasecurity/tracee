// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/un.h>
#include <uapi/linux/utsname.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/version.h>

#define MAXARG 20
#define MAX_STRING_SIZE     (1 << 12)     // Choosing this value to be the same as PATH_MAX (4096)
#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define SUBMIT_BUFSIZE      (1 << 14)     // Need to be power of 2
#define PATH_PREFIX_SIZE    16

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
#define OPEN_FLAGS_T  13UL
#define EXEC_FLAGS_T  14UL
#define SOCK_DOM_T    15UL
#define SOCK_TYPE_T   16UL
#define CAP_T         17UL
#define SYSCALL_T     18UL
#define PROT_FLAGS_T  19UL
#define ACCESS_MODE_T 20UL
#define PTRACE_REQ_T  21UL
#define PRCTL_OPT_T   22UL
#define TYPE_MAX      255UL

#define CONFIG_CONT_MODE       0
#define CONFIG_SHOW_SYSCALL    1
#define CONFIG_EXEC_ENV        2
#define CONFIG_CAPTURE_FILES   3

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Minimal required kernel version is 4.14
#endif

/*==================================== ENUMS =================================*/

enum event_id {
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYS_STAT,
    SYS_FSTAT,
    SYS_LSTAT,
    SYS_POLL,
    SYS_LSEEK,
    SYS_MMAP,
    SYS_MPROTECT,
    SYS_MUNMAP,
    SYS_BRK,
    SYS_RT_SIGACTION,
    SYS_RT_SIGPROCMASK,
    SYS_RT_SIGRETURN,
    SYS_IOCTL,
    SYS_PREAD64,
    SYS_PWRITE64,
    SYS_READV,
    SYS_WRITEV,
    SYS_ACCESS,
    SYS_PIPE,
    SYS_SELECT,
    SYS_SCHED_YIELD,
    SYS_MREMAP,
    SYS_MSYNC,
    SYS_MINCORE,
    SYS_MADVISE,
    SYS_SHMGET,
    SYS_SHMAT,
    SYS_SHMCTL,
    SYS_DUP,
    SYS_DUP2,
    SYS_PAUSE,
    SYS_NANOSLEEP,
    SYS_GETITIMER,
    SYS_ALARM,
    SYS_SETITIMER,
    SYS_GETPID,
    SYS_SENDFILE,
    SYS_SOCKET,
    SYS_CONNECT,
    SYS_ACCEPT,
    SYS_SENDTO,
    SYS_RECVFROM,
    SYS_SENDMSG,
    SYS_RECVMSG,
    SYS_SHUTDOWN,
    SYS_BIND,
    SYS_LISTEN,
    SYS_GETSOCKNAME,
    SYS_GETPEERNAME,
    SYS_SOCKETPAIR,
    SYS_SETSOCKOPT,
    SYS_GETSOCKOPT,
    SYS_CLONE,
    SYS_FORK,
    SYS_VFORK,
    SYS_EXECVE,
    SYS_EXIT,
    SYS_WAIT4,
    SYS_KILL,
    SYS_UNAME,
    SYS_SEMGET,
    SYS_SEMOP,
    SYS_SEMCTL,
    SYS_SHMDT,
    SYS_MSGGET,
    SYS_MSGSND,
    SYS_MSGRCV,
    SYS_MSGCTL,
    SYS_FCNTL,
    SYS_FLOCK,
    SYS_FSYNC,
    SYS_FDATASYNC,
    SYS_TRUNCATE,
    SYS_FTRUNCATE,
    SYS_GETDENTS,
    SYS_GETCWD,
    SYS_CHDIR,
    SYS_FCHDIR,
    SYS_RENAME,
    SYS_MKDIR,
    SYS_RMDIR,
    SYS_CREAT,
    SYS_LINK,
    SYS_UNLINK,
    SYS_SYMLINK,
    SYS_READLINK,
    SYS_CHMOD,
    SYS_FCHMOD,
    SYS_CHOWN,
    SYS_FCHOWN,
    SYS_LCHOWN,
    SYS_UMASK,
    SYS_GETTIMEOFDAY,
    SYS_GETRLIMIT,
    SYS_GETRUSAGE,
    SYS_SYSINFO,
    SYS_TIMES,
    SYS_PTRACE,
    SYS_GETUID,
    SYS_SYSLOG,
    SYS_GETGID,
    SYS_SETUID,
    SYS_SETGID,
    SYS_GETEUID,
    SYS_GETEGID,
    SYS_SETPGID,
    SYS_GETPPID,
    SYS_GETPGRP,
    SYS_SETSID,
    SYS_SETREUID,
    SYS_SETREGID,
    SYS_GETGROUPS,
    SYS_SETGROUPS,
    SYS_SETRESUID,
    SYS_GETRESUID,
    SYS_SETRESGID,
    SYS_GETRESGID,
    SYS_GETPGID,
    SYS_SETFSUID,
    SYS_SETFSGID,
    SYS_GETSID,
    SYS_CAPGET,
    SYS_CAPSET,
    SYS_RT_SIGPENDING,
    SYS_RT_SIGTIMEDWAIT,
    SYS_RT_SIGQUEUEINFO,
    SYS_RT_SIGSUSPEND,
    SYS_SIGALTSTACK,
    SYS_UTIME,
    SYS_MKNOD,
    SYS_USELIB,
    SYS_PERSONALITY,
    SYS_USTAT,
    SYS_STATFS,
    SYS_FSTATFS,
    SYS_SYSFS,
    SYS_GETPRIORITY,
    SYS_SETPRIORITY,
    SYS_SCHED_SETPARAM,
    SYS_SCHED_GETPARAM,
    SYS_SCHED_SETSCHEDULER,
    SYS_SCHED_GETSCHEDULER,
    SYS_SCHED_GET_PRIORITY_MAX,
    SYS_SCHED_GET_PRIORITY_MIN,
    SYS_SCHED_RR_GET_INTERVAL,
    SYS_MLOCK,
    SYS_MUNLOCK,
    SYS_MLOCKALL,
    SYS_MUNLOCKALL,
    SYS_VHANGUP,
    SYS_MODIFY_LDT,
    SYS_PIVOT_ROOT,
    SYS_SYSCTL,
    SYS_PRCTL,
    SYS_ARCH_PRCTL,
    SYS_ADJTIMEX,
    SYS_SETRLIMIT,
    SYS_CHROOT,
    SYS_SYNC,
    SYS_ACCT,
    SYS_SETTIMEOFDAY,
    SYS_MOUNT,
    SYS_UMOUNT,
    SYS_SWAPON,
    SYS_SWAPOFF,
    SYS_REBOOT,
    SYS_SETHOSTNAME,
    SYS_SETDOMAINNAME,
    SYS_IOPL,
    SYS_IOPERM,
    SYS_CREATE_MODULE,
    SYS_INIT_MODULE,
    SYS_DELETE_MODULE,
    SYS_GET_KERNEL_SYMS,
    SYS_QUERY_MODULE,
    SYS_QUOTACTL,
    SYS_NFSSERVCTL,
    SYS_GETPMSG,
    SYS_PUTPMSG,
    SYS_AFS,
    SYS_TUXCALL,
    SYS_SECURITY,
    SYS_GETTID,
    SYS_READAHEAD,
    SYS_SETXATTR,
    SYS_LSETXATTR,
    SYS_FSETXATTR,
    SYS_GETXATTR,
    SYS_LGETXATTR,
    SYS_FGETXATTR,
    SYS_LISTXATTR,
    SYS_LLISTXATTR,
    SYS_FLISTXATTR,
    SYS_REMOVEXATTR,
    SYS_LREMOVEXATTR,
    SYS_FREMOVEXATTR,
    SYS_TKILL,
    SYS_TIME,
    SYS_FUTEX,
    SYS_SCHED_SETAFFINITY,
    SYS_SCHED_GETAFFINITY,
    SYS_SET_THREAD_AREA,
    SYS_IO_SETUP,
    SYS_IO_DESTROY,
    SYS_IO_GETEVENTS,
    SYS_IO_SUBMIT,
    SYS_IO_CANCEL,
    SYS_GET_THREAD_AREA,
    SYS_LOOOKUP_DCOOKIE,
    SYS_EPOLL_CREATE,
    SYS_EPOLL_CTL_OLD,
    SYS_EPOLL_WAIT_OLD,
    SYS_REMAP_FILE_PAGES,
    SYS_GETDENTS64,
    SYS_SET_TID_ADDRESS,
    SYS_RESTART_SYSCALL,
    SYS_SEMTIMEDOP,
    SYS_FADVISE64,
    SYS_TIMER_CREATE,
    SYS_TIMER_SETTIME,
    SYS_TIMER_GETTIME,
    SYS_TIMER_GETOVERRUN,
    SYS_TIMER_DELETE,
    SYS_CLOCK_SETTIME,
    SYS_CLOCK_GETTIME,
    SYS_CLOCK_GETRES,
    SYS_CLOCK_NANOSLEEP,
    SYS_EXIT_GROUP,
    SYS_EPOLL_WAIT,
    SYS_EPOLL_CTL,
    SYS_TGKILL,
    SYS_UTIMES,
    SYS_VSERVER,
    SYS_MBIND,
    SYS_SET_MEMPOLICY,
    SYS_GET_MEMPOLICY,
    SYS_MQ_OPEN,
    SYS_MQ_UNLINK,
    SYS_MQ_TIMEDSEND,
    SYS_MQ_TIMEDRECEIVE,
    SYS_MQ_NOTIFY,
    SYS_MQ_GETSETATTR,
    SYS_KEXEC_LOAD,
    SYS_WAITID,
    SYS_ADD_KEY,
    SYS_REQUEST_KEY,
    SYS_KEYCTL,
    SYS_IOPRIO_SET,
    SYS_IOPRIO_GET,
    SYS_INOTIFY_INIT,
    SYS_INOTIFY_ADD_WATCH,
    SYS_INOTIFY_RM_WATCH,
    SYS_MIGRATE_PAGES,
    SYS_OPENAT,
    SYS_MKDIRAT,
    SYS_MKNODAT,
    SYS_FCHOWNAT,
    SYS_FUTIMESAT,
    SYS_NEWFSTATAT,
    SYS_UNLINKAT,
    SYS_RENAMEAT,
    SYS_LINKAT,
    SYS_SYMLINKAT,
    SYS_READLINKAT,
    SYS_FCHMODAT,
    SYS_FACCESSAT,
    SYS_PSELECT6,
    SYS_PPOLL,
    SYS_UNSHARE,
    SYS_SET_ROBUST_LIST,
    SYS_GET_ROBUST_LIST,
    SYS_SPLICE,
    SYS_TEE,
    SYS_SYNC_FILE_RANGE,
    SYS_VMSPLICE,
    SYS_MOVE_PAGES,
    SYS_UTIMENSAT,
    SYS_EPOLL_PWAIT,
    SYS_SIGNALFD,
    SYS_TIMERFD_CREATE,
    SYS_EVENTFD,
    SYS_FALLOCATE,
    SYS_TIMERFD_SETTIME,
    SYS_TIMERFD_GETTIME,
    SYS_ACCEPT4,
    SYS_SIGNALFD4,
    SYS_EVENTFD2,
    SYS_EPOLL_CREATE1,
    SYS_DUP3,
    SYS_PIPE2,
    SYS_IONOTIFY_INIT1,
    SYS_PREADV,
    SYS_PWRITEV,
    SYS_RT_TGSIGQUEUEINFO,
    SYS_PERF_EVENT_OPEN,
    SYS_RECVMMSG,
    SYS_FANOTIFY_INIT,
    SYS_FANOTIFY_MARK,
    SYS_PRLIMIT64,
    SYS_NAME_TO_HANDLE_AT,
    SYS_OPEN_BY_HANDLE_AT,
    SYS_CLOCK_ADJTIME,
    SYS_SYNCFS,
    SYS_SENDMMSG,
    SYS_SETNS,
    SYS_GETCPU,
    SYS_PROCESS_VM_READV,
    SYS_PROCESS_VM_WRITEV,
    SYS_KCMP,
    SYS_FINIT_MODULE,
    SYS_SCHED_SETATTR,
    SYS_SCHED_GETATTR,
    SYS_RENAMEAT2,
    SYS_SECCOMPP,
    SYS_GETRANDOM,
    SYS_MEMFD_CREATE,
    SYS_KEXEC_FILE_LOAD,
    SYS_BPF,
    SYS_EXECVEAT,
    SYS_USERFAULTFD,
    SYS_MEMBARRIER,
    SYS_MLOCK2,
    SYS_COPY_FILE_RANGE,
    SYS_PREADV2,
    SYS_PWRITEV2,
    SYS_PKEY_MPROTECT,
    SYS_PKEY_ALLOC,
    SYS_PKRY_FREE,
    SYS_STATX,
    SYS_IO_PGETEVENTS,
    SYS_RSEQ,
    RESERVED335,
    RESERVED336,
    RESERVED337,
    RESERVED338,
    RESERVED339,
    RESERVED340,
    RESERVED341,
    RESERVED342,
    RESERVED343,
    RESERVED344,
    RESERVED345,
    RESERVED346,
    RESERVED347,
    RESERVED348,
    RESERVED349,
    RAW_SYSCALLS,
    DO_EXIT,
    CAP_CAPABLE,
    SECURITY_BPRM_CHECK,
    SECURITY_FILE_OPEN,
    VFS_WRITE,
};

/*=============================== INTERNAL STRUCTS ===========================*/

typedef struct context {
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    enum event_id eventid;
    u8 argnum;
    s64 retval;
} context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} simple_buf_t;

typedef struct path_filter {
    char path[PATH_PREFIX_SIZE];
} path_filter_t;

typedef struct submit_buf {
    u32 off;
    u8 buf[SUBMIT_BUFSIZE];
} submit_buf_t;

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
BPF_HASH(pids_map, u32, u32);                       // Save container pid namespaces
BPF_HASH(args_map, u64, args_t);                    // Persist args info between function entry and return
BPF_HASH(vfs_args_map, u64, args_t);                // Persist args info between function entry and return
BPF_ARRAY(file_filter, path_filter_t, 3);           // Used to filter vfs_write events
BPF_PERCPU_ARRAY(submission_buf, submit_buf_t, 1);  // Buffer used to prepare event for perf_submit
BPF_PERCPU_ARRAY(string_buf, submit_buf_t, 1);      // Buffer used to prepare event for perf_submit
BPF_PERCPU_ARRAY(file_buf, simple_buf_t, 1);        // Buffer used to copy written files
BPF_PROG_ARRAY(prog_array, 10);                     // Used to store programs for tail calls

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                            // Events submission
BPF_PERF_OUTPUT(file_writes);                       // File writes events submission

/*================== KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return task->nsproxy->mnt_ns->ns.inum;
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return task->nsproxy->pid_ns_for_children->ns.inum;
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    // kernel 4.14-4.18:
    return task->pids[PIDTYPE_PID].pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#else
    // kernel 4.19 onwards:
    return task->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#endif
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    // kernel 4.14-4.18:
    return task->group_leader->pids[PIDTYPE_PID].pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#else
    // kernel 4.19 onwards:
    return task->group_leader->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#endif
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    // kernel 4.14-4.18:
    return task->real_parent->pids[PIDTYPE_PID].pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;
#else
    // kernel 4.19 onwards:
    return task->real_parent->thread_pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;
#endif
}

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    return task->nsproxy->uts_ns->name.nodename;
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    return task->real_parent->pid;
}

static __always_inline void get_syscall_args(struct pt_regs *ctx, args_t *args)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    args->args[0] = PT_REGS_PARM1(ctx);
    args->args[1] = PT_REGS_PARM2(ctx);
    args->args[2] = PT_REGS_PARM3(ctx);
    args->args[3] = PT_REGS_PARM4(ctx);
    args->args[4] = PT_REGS_PARM5(ctx);
    args->args[5] = PT_REGS_PARM6(ctx);
#else
    struct pt_regs * ctx2 = (struct pt_regs *)ctx->di;
    bpf_probe_read(&args->args[0], sizeof(args->args[0]), &ctx2->di);
    bpf_probe_read(&args->args[1], sizeof(args->args[1]), &ctx2->si);
    bpf_probe_read(&args->args[2], sizeof(args->args[2]), &ctx2->dx);
    bpf_probe_read(&args->args[3], sizeof(args->args[3]), &ctx2->r10);
    bpf_probe_read(&args->args[4], sizeof(args->args[4]), &ctx2->r8);
    bpf_probe_read(&args->args[5], sizeof(args->args[5]), &ctx2->r9);
#endif
}

static __always_inline struct pt_regs* get_task_pt_regs()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    void* task_stack_page = task->stack;
    void* __ptr = task_stack_page + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *)__ptr) - 1;
}

/*============================== HELPER FUNCTIONS ==============================*/

// re-define container_of as bcc complains
#define my_container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) * __mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return my_container_of(mnt, struct mount, mnt);
}

static __inline int is_prefix(char *prefix, char *str)
{
    int i;
    #pragma unroll
    for (i = 0; i < PATH_PREFIX_SIZE; prefix++, str++, i++) {
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

    u32 rc = 0;
    if (get_config(CONFIG_CONT_MODE))
        rc = lookup_pid_ns(task);
    else
        rc = lookup_pid();

    return rc;
}

static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    if (!should_trace())
        return -1;

    if (get_config(CONFIG_CONT_MODE)) {
        context->tid = get_task_ns_pid(task);
        context->pid = get_task_ns_tgid(task);
        context->ppid = get_task_ns_ppid(task);
    } else {
        u64 id = bpf_get_current_pid_tgid();
        context->tid = id;
        context->pid = id >> 32;
        context->ppid = get_task_ppid(task);
    }
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

static __always_inline submit_buf_t * get_submit_buf()
{
    int idx = 0;
    // Get per-cpu buffer
    return submission_buf.lookup(&idx);
}

static __always_inline int init_submit_buf()
{
    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return -1;

    submit_p->off = sizeof(context_t);

    return 0;
}

// Context will always be at the start of the submission buffer
// It may be needed to resave the context if the arguments number changed by logic
static __always_inline int save_context_to_buf(submit_buf_t *submit_p, void *ptr)
{
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static __always_inline int save_to_submit_buf(submit_buf_t *submit_p, void *ptr, int size, u8 type)
{
// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0)
        return 0;

    if (submit_p->off > SUBMIT_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument type
    int rc = bpf_probe_read(&(submit_p->buf[submit_p->off]), 1, &type);
    if (rc != 0)
        return 0;

    submit_p->off += 1;

    if (submit_p->off > SUBMIT_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Read into buffer
    rc = bpf_probe_read(&(submit_p->buf[submit_p->off]), size, ptr);
    if (rc == 0) {
        submit_p->off += size;
        return size;
    }

    // Remove argument type if read failed
    submit_p->off -= 1;
    return 0;
}

static __always_inline int save_str_to_buf(submit_buf_t *submit_p, void *ptr)
{
    if (submit_p->off > SUBMIT_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = STR_T;
    int rc = bpf_probe_read(&(submit_p->buf[submit_p->off & (SUBMIT_BUFSIZE-1)]), 1, &type);
    if (rc != 0)
        return 0;

    submit_p->off += 1;

    if (submit_p->off > SUBMIT_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // Satisfy validator for probe read
        return 0;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[submit_p->off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (submit_p->off > SUBMIT_BUFSIZE - sizeof(int))
            // Satisfy validator for probe read
            return 0;
        bpf_probe_read(&(submit_p->buf[submit_p->off]), sizeof(int), &sz);
        submit_p->off += sz + sizeof(int);
        return sz + sizeof(int);
    }

    // Remove argument type if read failed
    submit_p->off -= 1;
    return 0;
}

static __always_inline int get_path_string(submit_buf_t *string_p, struct path *path)
{
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = path->dentry;;
    struct vfsmount *vfsmnt = path->mnt;
    struct mount mnt;
    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt, sizeof(struct mount), mnt_p);

    string_p->off = SUBMIT_BUFSIZE - MAX_STRING_SIZE;

    #pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 30; i++) {
        if (dentry == vfsmnt->mnt_root || dentry == dentry->d_parent) {
            if (dentry != vfsmnt->mnt_root) {
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
        unsigned int len = (dentry->d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = string_p->off - len;
        // Is string buffer big enough for dentry name?
        if (off > SUBMIT_BUFSIZE - MAX_STRING_SIZE)
            break;
        int sz = bpf_probe_read_str(&(string_p->buf[off]), len, (void *)dentry->d_name.name);
        if (sz > 1) {
            string_p->off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[string_p->off & (SUBMIT_BUFSIZE-1)]), 1, &slash);
            string_p->off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = dentry->d_parent;
    }

    if (string_p->off == SUBMIT_BUFSIZE - MAX_STRING_SIZE) {
	// memfd files have no path in the filesystem -> extract their name
        string_p->off = 0;
        int sz = bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)dentry->d_name.name);
    } else {
        // Add leading slash
        string_p->off -= 1;
        bpf_probe_read(&(string_p->buf[string_p->off & (SUBMIT_BUFSIZE-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[SUBMIT_BUFSIZE - MAX_STRING_SIZE-1]), 1, &zero);
    }

    return string_p->off;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = submit_p->off & (SUBMIT_BUFSIZE-1);
    void * data = submit_p->buf;
    return events.perf_submit(ctx, data, size);
}

static __always_inline int save_argv(submit_buf_t *submit_p, void *ptr)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return save_str_to_buf(submit_p, (void *)(argp));
    }
    return 0;
}

static __always_inline int save_str_arr_to_buf(submit_buf_t *submit_p, const char __user *const __user *ptr)
{
    // mark string array start
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T);

    #pragma unroll
    for (int i = 0; i < MAXARG; i++) {
        if (save_argv(submit_p, (void *)&ptr[i]) == 0)
             goto out;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    save_str_to_buf(submit_p, (void *)ellipsis);
out:
    // mark string array end
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T);

    return 0;
}

static __always_inline int is_container()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    return lookup_pid_ns(task);
}

// Note: this function can't be nested!
// if inner kernel functions are called in syscall this may be a problem! - fix
static __always_inline int save_args(struct pt_regs *ctx, bool is_syscall)
{
    u64 id;
    args_t args = {};

    if (!should_trace())
        return 0;

    if (!is_syscall) {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    } else {
        get_syscall_args(ctx, &args);
    }

    id = bpf_get_current_pid_tgid();
    args_map.update(&id, &args);

    return 0;
}

// Note: this function can't be nested!
// if inner kernel functions are called in syscall this may be a problem! - fix
static __always_inline int load_args(args_t *args)
{
    args_t *saved_args;
    u64 id = bpf_get_current_pid_tgid();

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

    args_map.delete(&id);

    return 0;
}

#define ENC_ARG_TYPE(n, type) type<<(8*n)
#define ARG_TYPE0(type) ENC_ARG_TYPE(0, type)
#define ARG_TYPE1(type) ENC_ARG_TYPE(1, type)
#define ARG_TYPE2(type) ENC_ARG_TYPE(2, type)
#define ARG_TYPE3(type) ENC_ARG_TYPE(3, type)
#define ARG_TYPE4(type) ENC_ARG_TYPE(4, type)
#define ARG_TYPE5(type) ENC_ARG_TYPE(5, type)
#define DEC_ARG_TYPE(n, enc_type) ((enc_type>>(8*n))&0xFF)

static __always_inline int get_encoded_arg_num(u64 types)
{
    unsigned int i, argnum = 0;
    #pragma unroll
    for(i=0; i<6; i++)
    {
        if (DEC_ARG_TYPE(i, types) != NONE_T)
            argnum++;
    }
    return argnum;
}

static __always_inline int save_args_to_submit_buf(u64 types)
{
    unsigned int i;
    short family = 0;
    args_t args = {};

    if ((types == 0) || (load_args(&args) != 0))
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    #pragma unroll
    for(i=0; i<6; i++)
    {
        switch (DEC_ARG_TYPE(i, types))
        {
            case NONE_T:
                break;
            case INT_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), INT_T);
                break;
            case OPEN_FLAGS_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), OPEN_FLAGS_T);
                break;
            case UINT_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(unsigned int), UINT_T);
                break;
            case OFF_T_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(off_t), OFF_T_T);
                break;
            case DEV_T_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(dev_t), DEV_T_T);
                break;
            case MODE_T_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(mode_t), MODE_T_T);
                break;
            case LONG_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(long), LONG_T);
                break;
            case ULONG_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(unsigned long), ULONG_T);
                break;
            case SIZE_T_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(size_t), SIZE_T_T);
                break;
            case POINTER_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(void*), POINTER_T);
                break;
            case STR_T:
                save_str_to_buf(submit_p, (void *)args.args[i]);
                break;
            case SOCK_DOM_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), SOCK_DOM_T);
                break;
            case SOCK_TYPE_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), SOCK_TYPE_T);
                break;
            case PROT_FLAGS_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), PROT_FLAGS_T);
                break;
            case ACCESS_MODE_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), ACCESS_MODE_T);
                break;
            case SOCKADDR_T:
                if (args.args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void*)args.args[i]);
                    switch (family)
                    {
                        case AF_UNIX:
                            save_to_submit_buf(submit_p, (void*)(args.args[i]), sizeof(struct sockaddr_un), SOCKADDR_T);
                            break;
                        case AF_INET:
                            save_to_submit_buf(submit_p, (void*)(args.args[i]), sizeof(struct sockaddr_in), SOCKADDR_T);
                            break;
                        case AF_INET6:
                            save_to_submit_buf(submit_p, (void*)(args.args[i]), sizeof(struct sockaddr_in6), SOCKADDR_T);
                            break;
                        default:
                            save_to_submit_buf(submit_p, (void*)&family, sizeof(short), SOCKADDR_T);
                    }
                }
                break;
            case PTRACE_REQ_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), PTRACE_REQ_T);
                break;
            case PRCTL_OPT_T:
                save_to_submit_buf(submit_p, (void*)&(args.args[i]), sizeof(int), PRCTL_OPT_T);
                break;
        }
    }

    return 0;
}

static __always_inline int trace_ret_generic(struct pt_regs *ctx, u32 id, u64 types)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return -1;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = id;
    context.argnum = get_encoded_arg_num(types);
    context.retval = PT_REGS_RC(ctx);
    save_context_to_buf(submit_p, (void*)&context);
    save_args_to_submit_buf(types);

    events_perf_submit(ctx);
    return 0;
}

static __always_inline int trace_ret_generic_fork(struct pt_regs *ctx, u32 id, u64 types)
{
    int rc = trace_ret_generic(ctx, id, types);

    if (!rc && !get_config(CONFIG_CONT_MODE)) {
        u32 pid = PT_REGS_RC(ctx);
        add_pid_fork(pid);
    }

    return 0;
}

#define TRACE_ENT_SYSCALL(name)                                         \
int syscall__##name(struct pt_regs *ctx)                                \
{                                                                       \
    return save_args(ctx, true);                                        \
}

#define TRACE_ENT_FUNC(name)                                            \
int func__##name(struct pt_regs *ctx)                                   \
{                                                                       \
    return save_args(ctx, false);                                       \
}

#define TRACE_RET_FUNC(name, id, types)                                 \
int trace_ret_##name(struct pt_regs *ctx)                               \
{                                                                       \
    return trace_ret_generic(ctx, id, types);                           \
}

#define TRACE_RET_SYSCALL TRACE_RET_FUNC

#define TRACE_RET_FORK_SYSCALL(name, id, types)                         \
int trace_ret_##name(struct pt_regs *ctx)                               \
{                                                                       \
    return trace_ret_generic_fork(ctx, id, types);                      \
}

/*============================== SYSCALL HOOKS ==============================*/

// Note: race condition may occur if a malicious user changes memory content pointed by syscall arguments by concurrent threads!
// Consider using inner kernel functions (e.g. security_file_open) to avoid this
TRACE_ENT_SYSCALL(open);
TRACE_RET_SYSCALL(open, SYS_OPEN, ARG_TYPE0(STR_T)|ARG_TYPE1(OPEN_FLAGS_T));
TRACE_ENT_SYSCALL(openat);
TRACE_RET_SYSCALL(openat, SYS_OPENAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(OPEN_FLAGS_T));
TRACE_ENT_SYSCALL(creat);
TRACE_RET_SYSCALL(creat, SYS_CREAT, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(mmap);
TRACE_RET_SYSCALL(mmap, SYS_MMAP, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(PROT_FLAGS_T)|ARG_TYPE3(INT_T)|ARG_TYPE4(INT_T)|ARG_TYPE5(OFF_T_T));
TRACE_ENT_SYSCALL(mprotect);
TRACE_RET_SYSCALL(mprotect, SYS_MPROTECT, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(PROT_FLAGS_T));
TRACE_ENT_SYSCALL(pkey_mprotect);
TRACE_RET_SYSCALL(pkey_mprotect, SYS_PKEY_MPROTECT, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(PROT_FLAGS_T)|ARG_TYPE3(INT_T));
TRACE_ENT_SYSCALL(mknod);
TRACE_RET_SYSCALL(mknod, SYS_MKNOD, ARG_TYPE0(STR_T)|ARG_TYPE1(MODE_T_T)|ARG_TYPE2(DEV_T_T));
TRACE_ENT_SYSCALL(mknodat);
TRACE_RET_SYSCALL(mknodat, SYS_MKNODAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(MODE_T_T)|ARG_TYPE3(DEV_T_T));
TRACE_ENT_SYSCALL(memfd_create);
TRACE_RET_SYSCALL(memfd_create, SYS_MEMFD_CREATE, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(dup);
TRACE_RET_SYSCALL(dup, SYS_DUP, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(dup2);
TRACE_RET_SYSCALL(dup2, SYS_DUP2, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(dup3);
TRACE_RET_SYSCALL(dup3, SYS_DUP3, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T));
TRACE_ENT_SYSCALL(newstat);
TRACE_RET_SYSCALL(newstat, SYS_STAT, ARG_TYPE0(STR_T));
TRACE_ENT_SYSCALL(newlstat);
TRACE_RET_SYSCALL(newlstat, SYS_LSTAT, ARG_TYPE0(STR_T));
TRACE_ENT_SYSCALL(newfstat);
TRACE_RET_SYSCALL(newfstat, SYS_FSTAT, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(socket);
TRACE_RET_SYSCALL(socket, SYS_SOCKET, ARG_TYPE0(SOCK_DOM_T)|ARG_TYPE1(SOCK_TYPE_T)|ARG_TYPE2(INT_T));
TRACE_ENT_SYSCALL(close);
TRACE_RET_SYSCALL(close, SYS_CLOSE, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(ioctl);
TRACE_RET_SYSCALL(ioctl, SYS_IOCTL, ARG_TYPE0(INT_T)|ARG_TYPE1(ULONG_T));
TRACE_ENT_SYSCALL(access);
TRACE_RET_SYSCALL(access, SYS_ACCESS, ARG_TYPE0(STR_T)|ARG_TYPE1(ACCESS_MODE_T));
TRACE_ENT_SYSCALL(faccessat);
TRACE_RET_SYSCALL(faccessat, SYS_FACCESSAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(ACCESS_MODE_T)|ARG_TYPE3(INT_T));
TRACE_ENT_SYSCALL(kill);
TRACE_RET_SYSCALL(kill, SYS_KILL, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(listen);
TRACE_RET_SYSCALL(listen, SYS_LISTEN, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(connect);
TRACE_RET_SYSCALL(connect, SYS_CONNECT, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_SYSCALL(accept);
TRACE_RET_SYSCALL(accept, SYS_ACCEPT, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_SYSCALL(accept4);
TRACE_RET_SYSCALL(accept4, SYS_ACCEPT4, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_SYSCALL(bind);
TRACE_RET_SYSCALL(bind, SYS_BIND, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_SYSCALL(getsockname);
TRACE_RET_SYSCALL(getsockname, SYS_GETSOCKNAME, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_SYSCALL(prctl);
TRACE_RET_SYSCALL(prctl, SYS_PRCTL, ARG_TYPE0(PRCTL_OPT_T)|ARG_TYPE1(ULONG_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(ULONG_T)|ARG_TYPE4(ULONG_T));
TRACE_ENT_SYSCALL(ptrace);
TRACE_RET_SYSCALL(ptrace, SYS_PTRACE, ARG_TYPE0(PTRACE_REQ_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(POINTER_T)|ARG_TYPE3(POINTER_T));
TRACE_ENT_SYSCALL(process_vm_writev);
TRACE_RET_SYSCALL(process_vm_writev, SYS_PROCESS_VM_WRITEV, ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(POINTER_T)|ARG_TYPE4(ULONG_T)|ARG_TYPE5(ULONG_T));
TRACE_ENT_SYSCALL(process_vm_readv);
TRACE_RET_SYSCALL(process_vm_readv, SYS_PROCESS_VM_READV, ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(POINTER_T)|ARG_TYPE4(ULONG_T)|ARG_TYPE5(ULONG_T));
TRACE_ENT_SYSCALL(init_module);
TRACE_RET_SYSCALL(init_module, SYS_INIT_MODULE, ARG_TYPE0(POINTER_T)|ARG_TYPE1(ULONG_T)|ARG_TYPE2(STR_T));
TRACE_ENT_SYSCALL(finit_module);
TRACE_RET_SYSCALL(finit_module, SYS_FINIT_MODULE, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T));
TRACE_ENT_SYSCALL(delete_module);
TRACE_RET_SYSCALL(delete_module, SYS_DELETE_MODULE, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(symlink);
TRACE_RET_SYSCALL(symlink, SYS_SYMLINK, ARG_TYPE0(STR_T)|ARG_TYPE1(STR_T));
TRACE_ENT_SYSCALL(symlinkat);
TRACE_RET_SYSCALL(symlinkat, SYS_SYMLINKAT, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(STR_T));
TRACE_ENT_SYSCALL(getdents);
TRACE_RET_SYSCALL(getdents, SYS_GETDENTS, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(getdents64);
TRACE_RET_SYSCALL(getdents64, SYS_GETDENTS64, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(mount);
TRACE_RET_SYSCALL(mount, SYS_MOUNT, ARG_TYPE0(STR_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(STR_T)|ARG_TYPE3(ULONG_T));
TRACE_ENT_SYSCALL(umount);
TRACE_RET_SYSCALL(umount, SYS_UMOUNT, ARG_TYPE0(STR_T));
TRACE_ENT_SYSCALL(unlink);
TRACE_RET_SYSCALL(unlink, SYS_UNLINK, ARG_TYPE0(STR_T));
TRACE_ENT_SYSCALL(unlinkat);
TRACE_RET_SYSCALL(unlinkat, SYS_UNLINKAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T));
TRACE_ENT_SYSCALL(setuid);
TRACE_RET_SYSCALL(setuid, SYS_SETUID, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(setgid);
TRACE_RET_SYSCALL(setgid, SYS_SETGID, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(setfsuid);
TRACE_RET_SYSCALL(setfsuid, SYS_SETFSUID, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(setfsgid);
TRACE_RET_SYSCALL(setfsgid, SYS_SETFSGID, ARG_TYPE0(INT_T));
TRACE_ENT_SYSCALL(setreuid);
TRACE_RET_SYSCALL(setreuid, SYS_SETREUID, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(setregid);
TRACE_RET_SYSCALL(setregid, SYS_SETREGID, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(setresuid);
TRACE_RET_SYSCALL(setresuid, SYS_SETRESUID, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T));
TRACE_ENT_SYSCALL(setresgid);
TRACE_RET_SYSCALL(setresgid, SYS_SETRESGID, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T));
TRACE_ENT_SYSCALL(chown);
TRACE_RET_SYSCALL(chown, SYS_CHOWN, ARG_TYPE0(STR_T)|ARG_TYPE1(UINT_T)|ARG_TYPE2(UINT_T));
TRACE_ENT_SYSCALL(fchown);
TRACE_RET_SYSCALL(fchown, SYS_FCHOWN, ARG_TYPE0(INT_T)|ARG_TYPE1(UINT_T)|ARG_TYPE2(UINT_T));
TRACE_ENT_SYSCALL(lchown);
TRACE_RET_SYSCALL(lchown, SYS_LCHOWN, ARG_TYPE0(STR_T)|ARG_TYPE1(UINT_T)|ARG_TYPE2(UINT_T));
TRACE_ENT_SYSCALL(fchownat);
TRACE_RET_SYSCALL(fchownat, SYS_FCHOWNAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(UINT_T)|ARG_TYPE3(UINT_T)|ARG_TYPE4(INT_T));
TRACE_ENT_SYSCALL(chmod);
TRACE_RET_SYSCALL(chmod, SYS_CHMOD, ARG_TYPE0(STR_T)|ARG_TYPE1(MODE_T_T));
TRACE_ENT_SYSCALL(fchmod);
TRACE_RET_SYSCALL(fchmod, SYS_FCHMOD, ARG_TYPE0(INT_T)|ARG_TYPE1(MODE_T_T));
TRACE_ENT_SYSCALL(fchmodat);
TRACE_RET_SYSCALL(fchmodat, SYS_FCHMODAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(MODE_T_T)|ARG_TYPE3(INT_T));

TRACE_ENT_SYSCALL(fork);
TRACE_RET_FORK_SYSCALL(fork, SYS_FORK, 0);
TRACE_ENT_SYSCALL(vfork);
TRACE_RET_FORK_SYSCALL(vfork, SYS_VFORK, 0);
TRACE_ENT_SYSCALL(clone);
TRACE_RET_FORK_SYSCALL(clone, SYS_CLONE, 0);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = RAW_SYSCALLS;
    context.argnum = 1;
    context.retval = 0;

    save_context_to_buf(submit_p, (void*)&context);

    save_to_submit_buf(submit_p, (void*)&(args->id), sizeof(int), INT_T);
    events_perf_submit((struct pt_regs *)args);
    
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    context_t context = {};

    u32 ret = 0;
    if (get_config(CONFIG_CONT_MODE))
        ret = add_pid_ns_if_needed();
    else
        ret = add_pid();

    if (ret == 0)
        return 0;

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    int show_env = get_config(CONFIG_EXEC_ENV);

    context.eventid = SYS_EXECVE;
    if (show_env)
        context.argnum = 3;
    else
        context.argnum = 2;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_context_to_buf(submit_p, (void*)&context);

    save_str_to_buf(submit_p, (void *)filename);
    save_str_arr_to_buf(submit_p, __argv);
    if (show_env)
        save_str_arr_to_buf(submit_p, __envp);

    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execve(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVE;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

int syscall__execveat(struct pt_regs *ctx,
    const int dirfd,
    const char __user *pathname,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp,
    const int flags)
{
    context_t context = {};

    u32 ret = 0;
    if (get_config(CONFIG_CONT_MODE))
        ret = add_pid_ns_if_needed();
    else
        ret = add_pid();

    if (ret == 0)
        return 0;

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    int show_env = get_config(CONFIG_EXEC_ENV);

    context.eventid = SYS_EXECVEAT;
    if (show_env)
        context.argnum = 5;
    else
        context.argnum = 4;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_context_to_buf(submit_p, (void*)&context);

    save_to_submit_buf(submit_p, (void*)&dirfd, sizeof(int), INT_T);
    save_str_to_buf(submit_p, (void *)pathname);
    save_str_arr_to_buf(submit_p, __argv);
    if (show_env)
        save_str_arr_to_buf(submit_p, __envp);
    save_to_submit_buf(submit_p, (void*)&flags, sizeof(int), EXEC_FLAGS_T);

    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execveat(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

int trace_do_exit(struct pt_regs *ctx, long code)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = DO_EXIT;
    context.argnum = 0;
    context.retval = code;

    if (get_config(CONFIG_CONT_MODE))
        remove_pid_ns_if_needed();
    else
        remove_pid();

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

int trace_security_bprm_check(struct pt_regs *ctx, struct linux_binprm *bprm)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = SECURITY_BPRM_CHECK;
    context.argnum = 3;
    context.retval = 0;

    dev_t s_dev = bprm->file->f_inode->i_sb->s_dev;
    unsigned long inode_nr = (unsigned long)bprm->file->f_inode->i_ino;

    int idx = 0;
    // Get per-cpu string buffer
    submit_buf_t *string_p = string_buf.lookup(&idx);
    if (string_p == NULL)
        return -1;
    get_path_string(string_p, &bprm->file->f_path);

    save_context_to_buf(submit_p, (void*)&context);
    save_str_to_buf(submit_p, (void *)&string_p->buf[string_p->off]);
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T);
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T);

    events_perf_submit(ctx);
    return 0;
}

int trace_security_file_open(struct pt_regs *ctx, struct file *file)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = SECURITY_FILE_OPEN;
    context.argnum = 4;
    context.retval = 0;

    dev_t s_dev = file->f_inode->i_sb->s_dev;
    unsigned long inode_nr = (unsigned long)file->f_inode->i_ino;

    struct pt_regs *real_ctx = get_task_pt_regs();
    int syscall_nr = real_ctx->orig_ax;
    if (syscall_nr != 2 && syscall_nr != 257) // only monitor open and openat syscalls
        return 0;

    int idx = 0;
    // Get per-cpu string buffer
    submit_buf_t *string_p = string_buf.lookup(&idx);
    if (string_p == NULL)
        return -1;
    get_path_string(string_p, &file->f_path);

    save_context_to_buf(submit_p, (void*)&context);
    save_str_to_buf(submit_p, (void *)&string_p->buf[string_p->off]);
    save_to_submit_buf(submit_p, (void*)&file->f_flags, sizeof(int), OPEN_FLAGS_T);
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T);
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T);

    events_perf_submit(ctx);
    return 0;
}

int trace_cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int cap_opt)
{
    int audit;
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    context.eventid = CAP_CAPABLE;
    if (get_config(CONFIG_SHOW_SYSCALL))
        context.argnum = 2;
    else
        context.argnum = 1;

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);
    save_to_submit_buf(submit_p, (void*)&cap, sizeof(int), CAP_T);
    if (get_config(CONFIG_SHOW_SYSCALL)) {
        struct pt_regs *real_ctx = get_task_pt_regs();
        save_to_submit_buf(submit_p, (void*)&(real_ctx->orig_ax), sizeof(int), SYSCALL_T);
    }
    events_perf_submit(ctx);
    return 0;
};

int send_file(struct pt_regs *ctx)
{
    // Note: sending the data to the userspace have the following constraints:
    // 1. We need a buffer that we know it's exact size (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data can be overriden if userspace doesn't consume it fast enough

    int idx = 0;
    int i = 0;
    unsigned int chunk_size;

    u64 id = bpf_get_current_pid_tgid();

    args_t *saved_args = vfs_args_map.lookup(&id);
    if (saved_args == 0) {
        // missed entry or not traced
        return 0;
    }

    char *ptr               = (char*)         saved_args->args[0];
    dev_t s_dev             = (dev_t)         saved_args->args[1];
    unsigned long inode_nr  = (unsigned long) saved_args->args[2];
    loff_t start_pos        = (loff_t)        saved_args->args[3];
    unsigned int write_size = (unsigned int)  saved_args->args[4];

    vfs_args_map.delete(&id);

    if (write_size <= 0)
        return 0;

    simple_buf_t *file_buf_p = file_buf.lookup(&idx);
    if (file_buf_p == NULL)
        return 0;

#define F_MNT_NS      0
#define F_DEV_ID_OFF  (F_MNT_NS + sizeof(u32))
#define F_INODE_OFF   (F_DEV_ID_OFF + sizeof(dev_t))
#define F_SZ_OFF      (F_INODE_OFF + sizeof(unsigned long))
#define F_POS_OFF     (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF   (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE  (MAX_PERCPU_BUFSIZE - F_CHUNK_OFF - 4)

    u32 mnt_id = get_task_mnt_ns_id((struct task_struct *)bpf_get_current_task());
    bpf_probe_read((void **)&(file_buf_p->buf[F_MNT_NS]), sizeof(u32), &mnt_id);

    // Save device id and inode to be used in filename
    bpf_probe_read((void **)&(file_buf_p->buf[F_DEV_ID_OFF]), sizeof(dev_t), &s_dev);
    bpf_probe_read((void **)&(file_buf_p->buf[F_INODE_OFF]), sizeof(unsigned long), &inode_nr);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = write_size/F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

    // Handle full chunks in loop
    #pragma unroll
    for (i = 0; i < 110; i++) {
        // Dummy instruction, as break instruction can't be first with unroll optimization
        chunk_size = F_CHUNK_SIZE;

        if (i == full_chunk_num)
            break;

        // Save binary chunk and file position of write
        bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &start_pos);
        bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, ptr);
        ptr += F_CHUNK_SIZE;
        start_pos += F_CHUNK_SIZE;

        file_writes.perf_submit(ctx, data, F_CHUNK_OFF+F_CHUNK_SIZE);
    }

    chunk_size = write_size - i*F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        args_t args = {};
        args.args[0] = (unsigned long)ptr;
        args.args[1] = (unsigned long)s_dev;
        args.args[2] = (unsigned long)inode_nr;
        args.args[3] = (unsigned long)start_pos;
        args.args[4] = (unsigned long)chunk_size;
        vfs_args_map.update(&id, &args);

        // Handle the rest of the write recursively
        prog_array.call(ctx, 0);
        return 0;
    }

    // Save last chunk
    bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, ptr);
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
    bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &start_pos);

    // Satisfy validator by setting buffer bounds
    int size = (F_CHUNK_OFF+chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
    file_writes.perf_submit(ctx, data, size);

    return 0;
}

int trace_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    // We can't use save_args here as this is an inner kernel function, which will overwrite previously saved arguments
    // Use another map (vfs_args_map) instead

    u64 id;
    args_t args = {};

    if (!should_trace())
        return 0;

    args.args[0] = (unsigned long)file;
    args.args[1] = (unsigned long)buf;
    args.args[2] = (unsigned long)count;
    args.args[3] = (unsigned long)pos;

    id = bpf_get_current_pid_tgid();
    vfs_args_map.update(&id, &args);

    return 0;
}

int trace_ret_vfs_write(struct pt_regs *ctx)
{
    context_t context = {};
    struct path path;
    args_t *saved_args;
    args_t args = {};
    struct inode *inode;
    struct super_block *superblock;
    dev_t s_dev;
    unsigned long inode_nr;
    loff_t start_pos;

    if (init_context(&context) || init_submit_buf())
        return -1;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    saved_args = vfs_args_map.lookup(&id);
    if (saved_args == 0) {
        // missed entry or not traced
        return 0;
    }

    struct file *file      = (struct file *) saved_args->args[0];
    void *ptr              = (void*)         saved_args->args[1];
    size_t count           = (size_t)        saved_args->args[2];
    loff_t *pos            = (loff_t*)       saved_args->args[3];

    vfs_args_map.delete(&id);

    // Extract path of written file
    bpf_probe_read(&path, sizeof(struct path), &file->f_path);
    int idx = 0;
    // Get per-cpu string buffer
    submit_buf_t *string_p = string_buf.lookup(&idx);
    if (string_p == NULL)
        return -1;
    get_path_string(string_p, &path);

    idx = 0;
    path_filter_t *filter1_p = file_filter.lookup(&idx);
    idx = 1;
    path_filter_t *filter2_p = file_filter.lookup(&idx);
    idx = 2;
    path_filter_t *filter3_p = file_filter.lookup(&idx);
    if ((filter1_p == NULL) || (filter2_p == NULL) || (filter3_p == NULL))
        return -1;

    // Filter requested paths
    if (filter1_p->path[0]) {
        if (string_p->off <= SUBMIT_BUFSIZE - MAX_STRING_SIZE) {
            if (filter1_p->path[0] && is_prefix(filter1_p->path, &string_p->buf[string_p->off]))
                goto VFS_W_CONT;

            if (filter2_p->path[0] && is_prefix(filter2_p->path, &string_p->buf[string_p->off]))
                goto VFS_W_CONT;

            if (filter3_p->path[0] && is_prefix(filter3_p->path, &string_p->buf[string_p->off]))
                goto VFS_W_CONT;
        }
        return 0;
    }

VFS_W_CONT:
    // Extract device id, inode number and pos (offset)
    bpf_probe_read(&inode, sizeof(struct inode *), &file->f_inode);
    bpf_probe_read(&superblock, sizeof(struct super_block *), &inode->i_sb);
    bpf_probe_read(&s_dev, sizeof(dev_t), &superblock->s_dev);
    bpf_probe_read(&inode_nr, sizeof(unsigned long), &inode->i_ino);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= PT_REGS_RC(ctx);

    context.eventid = VFS_WRITE;
    context.argnum = 5;
    context.retval = PT_REGS_RC(ctx);
    save_context_to_buf(submit_p, &context);

    save_str_to_buf(submit_p, (void *)&string_p->buf[string_p->off]);
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T);
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T);
    save_to_submit_buf(submit_p, &count, sizeof(size_t), SIZE_T_T);
    save_to_submit_buf(submit_p, &start_pos, sizeof(off_t), OFF_T_T);

    // Submit vfs_write event
    events_perf_submit(ctx);

    args.args[0] = (unsigned long)ptr;
    args.args[1] = (unsigned long)s_dev;
    args.args[2] = (unsigned long)inode_nr;
    args.args[3] = (unsigned long)start_pos;
    args.args[4] = PT_REGS_RC(ctx);
    vfs_args_map.update(&id, &args);

    if (get_config(CONFIG_CAPTURE_FILES))
        // Send file data
        prog_array.call(ctx, 0);
    return 0;
}

