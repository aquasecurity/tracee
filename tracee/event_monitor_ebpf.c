/*
 * Authors:
 *     Yaniv Agman <yaniv@aquasec.com>
 *
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/utsname.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/version.h>

#define MAXARG 20
#define MAX_STRING_SIZE 4096                                // Choosing this value to be the same as PATH_MAX
#define SUBMIT_BUFSIZE  (2 << 13)                           // Need to be power of 2
#define SUBMIT_BUFSIZE_HALF   ((SUBMIT_BUFSIZE-1) >> 1)     // Bitmask for ebpf validator - this is why we need SUBMIT_BUFSIZE to be power of 2

#define NONE_T      0UL
#define INT_T       1UL
#define UINT_T      2UL
#define LONG_T      3UL
#define ULONG_T     4UL
#define OFF_T_T     5UL
#define MODE_T_T    6UL
#define DEV_T_T     7UL
#define SIZE_T_T    8UL
#define POINTER_T   9UL
#define STR_T       10UL
#define STR_ARR_T   11UL
#define SOCKADDR_T  12UL
#define OPENFLAGS_T 13UL
#define EXEC_FLAG_T 14UL
#define SOCK_DOM_T  15UL
#define SOCK_TYPE_T 16UL
#define CAP_T       17UL
#define TYPE_MAX    255UL

#define CONFIG_CONT_MODE    0

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
    DO_EXIT,
    CAP_CAPABLE,
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

/*=================================== MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                     // Various configurations
BPF_HASH(pids_map, u32, u32);                       // Save container pid namespaces
BPF_HASH(args_map, u64, args_t);                    // Persist args info between function entry and return
BPF_PERCPU_ARRAY(submission_buf, submit_buf_t, 1);  // Buffer used to prepare event for perf_submit

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                            // Events submission

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

/*============================== HELPER FUNCTIONS ==============================*/

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

static __always_inline int container_mode()
{
    u32 key = CONFIG_CONT_MODE;
    u32 *mode = config_map.lookup(&key);

    if (mode == NULL)
        return 0;

    return *mode;
}

static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 should_trace = 0;
    if (container_mode())
        should_trace = lookup_pid_ns(task);
    else
        should_trace = lookup_pid();

    // Check if we should trace this pid val
    if (should_trace == 0)
        return -1;

    if (container_mode()) {
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
    submit_buf_t *submit_p = submission_buf.lookup(&idx);
    if (submit_p == NULL)
        return NULL;

    return submit_p;
}

static __always_inline int init_submit_buf()
{
    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return -1;

    submit_p->off = 0;

    return 0;
}

static __always_inline int save_to_submit_buf(void *ptr, int size, u8 type)
{
    submit_buf_t *submit_p = get_submit_buf();

    if (submit_p == NULL)
        return 0;

    if (submit_p->off > SUBMIT_BUFSIZE_HALF)
        // not enough space - return
        return 0;

    // Save argument type
    if (type != 0) {
        int rc = bpf_probe_read((void **)&(submit_p->buf[submit_p->off & SUBMIT_BUFSIZE_HALF]), 1, &type);
        if (rc != 0)
            return 0;

        submit_p->off += 1;

        if (type == STR_ARR_T)
            return 0;
    }

    // Read into buffer
    int rc = bpf_probe_read((void **)&(submit_p->buf[submit_p->off & SUBMIT_BUFSIZE_HALF]), size, ptr);
    if (rc == 0) {
        submit_p->off += size;
        return size;
    }

    return 0;
}

static __always_inline int save_str_to_buf(void *ptr)
{
    submit_buf_t *submit_p = get_submit_buf();

    if (submit_p == NULL)
        return 0;

    if (submit_p->off > SUBMIT_BUFSIZE_HALF)
        // not enough space - return
        return 0;

    int type = STR_T;
    // Save argument type
    int rc = bpf_probe_read((void **)&(submit_p->buf[submit_p->off & SUBMIT_BUFSIZE_HALF]), 1, &type);
    if (rc != 0)
        return 0;

    submit_p->off += 1;

    // Read into buffer
    int sz = bpf_probe_read_str((void **)&(submit_p->buf[(submit_p->off + sizeof(int)) & SUBMIT_BUFSIZE_HALF]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        bpf_probe_read((void **)&(submit_p->buf[submit_p->off & SUBMIT_BUFSIZE_HALF]), sizeof(int), &sz);
        submit_p->off += sz + sizeof(int);
        return sz + sizeof(int);
    } else {
        sz = 0;
        bpf_probe_read((void **)&(submit_p->buf[submit_p->off & SUBMIT_BUFSIZE_HALF]), sizeof(int), &sz);
        submit_p->off += sizeof(int);
        return sizeof(int);
    }

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = ((submit_p->off - 1) & SUBMIT_BUFSIZE_HALF) + 1;
    void * data = submit_p->buf;
    return events.perf_submit(ctx, data, size);
}

static __always_inline int save_argv(struct pt_regs *ctx, void *ptr)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return save_str_to_buf((void *)(argp));
    }
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

    u32 should_trace = 0;
    if (container_mode())
        should_trace = is_container();
    else
        should_trace = lookup_pid();

    if (!should_trace)
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

    #pragma unroll
    for(i=0; i<6; i++)
    {
        switch (DEC_ARG_TYPE(i, types))
        {
            case NONE_T:
                break;
            case INT_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(int), INT_T);
                break;
            case OPENFLAGS_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(int), OPENFLAGS_T);
                break;
            case UINT_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(unsigned int), UINT_T);
                break;
            case OFF_T_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(off_t), OFF_T_T);
                break;
            case DEV_T_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(dev_t), DEV_T_T);
                break;
            case MODE_T_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(mode_t), MODE_T_T);
                break;
            case LONG_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(long), LONG_T);
                break;
            case ULONG_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(unsigned long), ULONG_T);
                break;
            case SIZE_T_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(size_t), SIZE_T_T);
                break;
            case POINTER_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(void*), POINTER_T);
                break;
            case STR_T:
                save_str_to_buf((void *)args.args[i]);
                break;
            case SOCK_DOM_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(int), SOCK_DOM_T);
                break;
            case SOCK_TYPE_T:
                save_to_submit_buf((void*)&(args.args[i]), sizeof(int), SOCK_TYPE_T);
                break;
            case SOCKADDR_T:
                if (args.args[i])
                    bpf_probe_read(&family, sizeof(short), (void*)args.args[i]);
                save_to_submit_buf((void*)&family, sizeof(short), SOCKADDR_T);
                break;
        }
    }

    return 0;
}

static __always_inline int trace_ret_generic(struct pt_regs *ctx, u32 id, u64 types)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    context.eventid = id;
    context.argnum = get_encoded_arg_num(types);
    context.retval = PT_REGS_RC(ctx);
    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
    save_args_to_submit_buf(types);

    events_perf_submit(ctx);
    return 0;
}

static __always_inline int trace_ret_generic_fork(struct pt_regs *ctx, u32 id, u64 types)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    if (!container_mode()) {
        u32 pid = PT_REGS_RC(ctx);
        add_pid_fork(pid);
    }

    context.eventid = id;
    context.argnum = get_encoded_arg_num(types);
    context.retval = PT_REGS_RC(ctx);
    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
    save_args_to_submit_buf(types);

    events_perf_submit(ctx);
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
TRACE_RET_SYSCALL(open, SYS_OPEN, ARG_TYPE0(STR_T)|ARG_TYPE1(OPENFLAGS_T));
TRACE_ENT_SYSCALL(openat);
TRACE_RET_SYSCALL(openat, SYS_OPENAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(OPENFLAGS_T));
TRACE_ENT_SYSCALL(creat);
TRACE_RET_SYSCALL(creat, SYS_CREAT, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(mmap);
TRACE_RET_SYSCALL(mmap, SYS_MMAP, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T)|ARG_TYPE4(INT_T)|ARG_TYPE5(OFF_T_T));
TRACE_ENT_SYSCALL(mprotect);
TRACE_RET_SYSCALL(mprotect, SYS_MPROTECT, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T));
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
TRACE_RET_SYSCALL(access, SYS_ACCESS, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_SYSCALL(faccessat);
TRACE_RET_SYSCALL(faccessat, SYS_FACCESSAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T));
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
TRACE_RET_SYSCALL(prctl, SYS_PRCTL, ARG_TYPE0(INT_T)|ARG_TYPE1(ULONG_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(ULONG_T)|ARG_TYPE4(ULONG_T));
TRACE_ENT_SYSCALL(ptrace);
TRACE_RET_SYSCALL(ptrace, SYS_PTRACE, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(POINTER_T)|ARG_TYPE3(POINTER_T));
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

TRACE_ENT_SYSCALL(fork);
TRACE_RET_FORK_SYSCALL(fork, SYS_FORK, 0);
TRACE_ENT_SYSCALL(vfork);
TRACE_RET_FORK_SYSCALL(vfork, SYS_VFORK, 0);
TRACE_ENT_SYSCALL(clone);
TRACE_RET_FORK_SYSCALL(clone, SYS_CLONE, 0);

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    context_t context = {};

    u32 ret = 0;
    if (container_mode())
        ret = add_pid_ns_if_needed();
    else
        ret = add_pid();

    if (ret == 0)
        return 0;

    if (init_context(&context) || init_submit_buf())
        return 0;

    context.eventid = SYS_EXECVE;
    context.argnum = 2;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
    save_str_to_buf((void *)filename);

    // mark string array start
    save_to_submit_buf(NULL, 0, STR_ARR_T);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (save_argv(ctx, (void *)&__argv[i]) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    save_str_to_buf((void *)ellipsis);
out:
    // mark string array end
    save_to_submit_buf(NULL, 0, STR_ARR_T);
    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execve(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    context.eventid = SYS_EXECVE;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
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
    if (container_mode())
        ret = add_pid_ns_if_needed();
    else
        ret = add_pid();

    if (ret == 0)
        return 0;

    if (init_context(&context) || init_submit_buf())
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.argnum = 4;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
    save_to_submit_buf((void*)&dirfd, sizeof(int), INT_T);

    save_str_to_buf((void *)pathname);

    // mark string array start
    save_to_submit_buf(NULL, 0, STR_ARR_T);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (save_argv(ctx, (void *)&__argv[i]) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    save_str_to_buf((void *)ellipsis);
out:
    // mark string array end
    save_to_submit_buf(NULL, 0, STR_ARR_T);
    save_to_submit_buf((void*)&flags, sizeof(int), EXEC_FLAG_T);
    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execveat(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

int trace_do_exit(struct pt_regs *ctx, long code)
{
    context_t context = {};

    if (init_context(&context) || init_submit_buf())
        return 0;

    context.eventid = DO_EXIT;
    context.argnum = 0;
    context.retval = code;

    if (container_mode())
        remove_pid_ns_if_needed();
    else
        remove_pid();

    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
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

    context.eventid = CAP_CAPABLE;
    context.argnum = 1;

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    save_to_submit_buf((void*)&context, sizeof(context_t), NONE_T);
    save_to_submit_buf((void*)&cap, sizeof(int), CAP_T);
    events_perf_submit(ctx);
    return 0;
};
