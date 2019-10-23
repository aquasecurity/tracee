/*
 * Authors:
 *     Yaniv Agman <yaniv@aquasec.com>
 *
 */

// todo: execve: handle envp, put argv and envp in a list instead being different param for each arg
// todo: when a new file is written - copy it offline
// todo: add syscalls: "getdirents", "uname"
// todo: add full sockaddr struct to: "connect", "accept", "bind", "getsockname"
// todo: add commit_creds tracing to detect kernel exploits
// todo: macro of function which includes entry and exit
// todo: fix problem with execveat - can't see pathname
// todo: add check for head and tail to avoid overflow!
// todo: add a "do extra" function inside the macro, so we can also include special cases (e.g. is_capable)
// todo: add support for kernel versions 4.19 onward (see kernel version dependant section below)
// todo: change submission_buf size from 32 to num_of_cpu which can be determined by userspace and set and compiled accordingly

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>

#define MAX_STRING_SIZE 4096                                // Choosing this value to be the same as PATH_MAX
#define SUBMIT_BUFSIZE  524288                              // Need to be power of 2
#define SUBMIT_BUFSIZE_HALF   ((SUBMIT_BUFSIZE-1) >> 1)     // Bitmask for ebpf validator - this is why we need STR_BUFSIZE to be power of 2
// Percpu buffer max possible size is (2^17)/log(num_of_cpus)

/*==================================== ENUMS =================================*/

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

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
    enum event_id eventid;
    s64 retval;
} context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

// This will be submitted with perf_submit - keep as small as possible
typedef struct event {
    u32 start_off;              // event start offset in submit ring buffer
    u32 max_off;                // lets user space know when buffer is wrapped, without assuming any buffer size
    u32 end_off;                // event end offset in submit ring buffer
} event_t;

typedef struct submit_buf {
    int head, tail;
    u8 buf[SUBMIT_BUFSIZE];
} submit_buf_t;

/*================================ KERNEL STRUCTS =============================*/

struct mnt_namespace {
    atomic_t        count;
    struct ns_common    ns;
    // ...
};

/*=================================== MAPS =====================================*/

BPF_HASH(cont_pidns, u32, u32);                     // Save container pid namespaces
BPF_HASH(args_map, u64, args_t);                    // Persist args info between function entry and return
BPF_PERCPU_ARRAY(event_submit, event_t, 1);         // Event to perf_submit
BPF_ARRAY(submission_buf, submit_buf_t, 32);        // Buffer for events. Not using percpu array as it caused insufficient memory with large buffer size.

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
    // We don't use bpf_get_current_pid_tgid() as it is not pid namespace aware
    // return bpf_get_current_pid_tgid() >> 32;

    // kernel 4.19:
    // return task->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;

    // kernel 4.14-4.18:
    return task->pids[PIDTYPE_PID].pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    // We don't use bpf_get_current_pid_tgid() as it is not pid namespace aware
    // return bpf_get_current_pid_tgid();

    // kernel 4.14-4.18:
    return task->group_leader->pids[PIDTYPE_PID].pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    // kernel 4.19:
    // return task->real_parent->tgid;
    // return task->real_parent->thread_pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;

    // kernel 4.14-4.18:
    return task->real_parent->pids[PIDTYPE_PID].pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;
}

/*============================== HELPER FUNCTIONS ==============================*/

static __always_inline u32 lookup_pid_ns(struct task_struct *task)
{
    u32 task_pid_ns = get_task_pid_ns_id(task);

    u32 *pid_ns = cont_pidns.lookup(&task_pid_ns);
    if (pid_ns == 0)
        return 0;

    return *pid_ns;
}

static __always_inline u32 add_pid_ns_if_needed()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (cont_pidns.lookup(&pid_ns) != 0)
        // Container pidns was already added to map
        return pid_ns;

    // If pid equals 1 - start tracing the container
    if (get_task_ns_pid(task) == 1) {
        // A new container/pod was started - add pid namespace to map
        cont_pidns.update(&pid_ns, &pid_ns);
        return pid_ns;
    }

    // Not a container/pod
    return 0;
}

static __always_inline void remove_pid_ns_if_needed()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (cont_pidns.lookup(&pid_ns) != 0) {
        // If pid equals 1 - stop tracing this pid namespace
        if (get_task_ns_pid(task) == 1) {
            cont_pidns.delete(&pid_ns);
        }
    }
}

static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    // check if we should trace this pid namespace
    u32 pid_ns = lookup_pid_ns(task);
    if (pid_ns == 0)
        return -1;

    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns()/1000;

    return 0;
}

static __always_inline event_t * get_event()
{
    int idx = 0;
    // get per-cpu buffer
    event_t *event = event_submit.lookup(&idx);
    if (event == NULL)
        return NULL;

    return event;
}

static __always_inline submit_buf_t * get_submit_buf()
{
    int key = bpf_get_smp_processor_id();
    submit_buf_t *submit_p = submission_buf.lookup(&key);
    if (submit_p == NULL)
        return NULL;

    if (submit_p->head > SUBMIT_BUFSIZE_HALF) {
        event_t *event_p = get_event();
        if (event_p == NULL)
            return NULL;

        // save the max offset so user space can know until where to read
        event_p->max_off = submit_p->head;
        // not enough space - return to ring buffer start (ebpf validator forces bounds check)
        submit_p->head = 0;
    }
    return submit_p;
}

static __always_inline int save_to_submit_buf(void *ptr, int size)
{
    submit_buf_t *submit_p = get_submit_buf();

    if (submit_p == NULL)
        return 0;

    // todo: add tail < head check + new event if not enough space
    // read into buffer
    int rc = bpf_probe_read((void **)&(submit_p->buf[submit_p->head & SUBMIT_BUFSIZE_HALF]), size, ptr);
    if (rc == 0) {
        submit_p->head += size;
        return size;
    }

    return 0;
}

static __always_inline int save_str_to_buf(void *ptr)
{
    submit_buf_t *submit_p = get_submit_buf();

    if (submit_p == NULL)
        return 0;

    // todo: add tail < head check + new event if not enough space
    // read into buffer
    int sz = bpf_probe_read_str((void **)&(submit_p->buf[(submit_p->head + sizeof(int)) & SUBMIT_BUFSIZE_HALF]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        bpf_probe_read((void **)&(submit_p->buf[submit_p->head & SUBMIT_BUFSIZE_HALF]), sizeof(int), &sz);
        submit_p->head += sz + sizeof(int);
        return sz + sizeof(int);
    }

    return 0;
}

static __always_inline int init_event()
{
    event_t *event_p = get_event();
    if (event_p == NULL)
        return -1;

    submit_buf_t *submit_p = get_submit_buf();
    if (submit_p == NULL)
        return -1;

    event_p->start_off = submit_p->head;
    event_p->max_off = SUBMIT_BUFSIZE;

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    event_t *event_p = get_event();
    if (event_p == NULL)
        return -1;

    int key = bpf_get_smp_processor_id();
    submit_buf_t *submit_p = submission_buf.lookup(&key);
    if (submit_p != NULL)
        event_p->end_off = submit_p->head;
    // write max_off and end_off to map (at start_off) so we can send only start_off as the event

    /* satisfy validator by setting buffer bounds */
    //int size = ((data_size - 1) & SUBMIT_BUFSIZE_HALF) + 1;
    return events.perf_submit(ctx, event_p, sizeof(event_t));
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

// Note: this function is not nested!
// if inner kernel functions are called in syscall this may be a problem! - fix
static __always_inline int save_args(struct pt_regs *ctx)
{
    u64 id;
    args_t args = {};

    if (!is_container())
        return 0;

    args.args[0] = PT_REGS_PARM1(ctx);
    args.args[1] = PT_REGS_PARM2(ctx);
    args.args[2] = PT_REGS_PARM3(ctx);
    args.args[3] = PT_REGS_PARM4(ctx);
    args.args[4] = PT_REGS_PARM5(ctx);
    args.args[5] = PT_REGS_PARM6(ctx);

    id = bpf_get_current_pid_tgid();
    args_map.update(&id, &args);

    return 0;
}

// Note: this function is not nested!
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

#define NONE        0
#define INT_T       1
#define LONG_T      2
#define POINTER_T   3
#define STR_T       4
#define OFF_T_T     5
#define MODE_T_T    6
#define DEV_T_T     7
#define SIZE_T_T    8
#define UINT_T      9
#define SOCKADDR_T  10
#define TYPE_MAX    16

#define ENC_ARG_TYPE(n, type) type<<(4*n)
#define ARG_TYPE0(type) ENC_ARG_TYPE(0, type)
#define ARG_TYPE1(type) ENC_ARG_TYPE(1, type)
#define ARG_TYPE2(type) ENC_ARG_TYPE(2, type)
#define ARG_TYPE3(type) ENC_ARG_TYPE(3, type)
#define ARG_TYPE4(type) ENC_ARG_TYPE(4, type)
#define ARG_TYPE5(type) ENC_ARG_TYPE(5, type)
#define DEC_ARG_TYPE(n, enc_type) ((enc_type>>(4*n))&0xF)

static __always_inline int save_args_to_submit_buf(int types)
{
    unsigned int i;
    args_t args = {};

    if ((types == 0) || (load_args(&args) != 0))
        return 0;

    #pragma unroll
    for(i=0; i<6; i++)
    {
        if (DEC_ARG_TYPE(i, types) == INT_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(int));
        else if (DEC_ARG_TYPE(i, types) == UINT_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(unsigned int));
        else if (DEC_ARG_TYPE(i, types) == OFF_T_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(off_t));
        else if (DEC_ARG_TYPE(i, types) == DEV_T_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(dev_t));
        else if (DEC_ARG_TYPE(i, types) == MODE_T_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(mode_t));
        else if (DEC_ARG_TYPE(i, types) == LONG_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(unsigned long));
        else if (DEC_ARG_TYPE(i, types) == SIZE_T_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(size_t));
        else if (DEC_ARG_TYPE(i, types) == POINTER_T)
            save_to_submit_buf((void*)&(args.args[i]), sizeof(void*));
        else if (DEC_ARG_TYPE(i, types) == STR_T)
            save_str_to_buf((void *)args.args[i]);
        else if (DEC_ARG_TYPE(i, types) == SOCKADDR_T) {
            short family = 0;
            if (args.args[i])
                bpf_probe_read(&family, sizeof(short), (void*)args.args[i]);
            save_to_submit_buf((void*)&family, sizeof(short));
        }
    }

    return 0;
}

#define TRACE_ENT_FUNC(name)               \
int trace_##name(struct pt_regs *ctx)      \
{                                          \
    return save_args(ctx);                 \
}

#define TRACE_RET_FUNC(name, id, types)                                 \
int trace_ret_##name(struct pt_regs *ctx)                               \
{                                                                       \
    context_t context = {};                                             \
                                                                        \
    if (init_context(&context) || init_event())                         \
        return 0;                                                       \
                                                                        \
    context.eventid = id;                                               \
    context.retval = PT_REGS_RC(ctx);                                   \
    save_to_submit_buf((void*)&context, sizeof(context_t));             \
    save_args_to_submit_buf(types);                                     \
                                                                        \
    events_perf_submit(ctx);                                            \
    return 0;                                                           \
}

/*============================== SYSCALL HOOKS ==============================*/

// Note: race condition may occur if a malicious user changes the arguments concurrently
// consider using security_file_open instead
TRACE_ENT_FUNC(sys_open);
TRACE_RET_FUNC(sys_open, SYS_OPEN, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_openat);
TRACE_RET_FUNC(sys_openat, SYS_OPENAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T));
TRACE_ENT_FUNC(sys_creat);
TRACE_RET_FUNC(sys_creat, SYS_CREAT, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_mmap);
TRACE_RET_FUNC(sys_mmap, SYS_MMAP, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T)|ARG_TYPE4(INT_T)|ARG_TYPE5(OFF_T_T));
TRACE_ENT_FUNC(sys_mprotect);
TRACE_RET_FUNC(sys_mprotect, SYS_MPROTECT, ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T));
TRACE_ENT_FUNC(sys_mknod);
TRACE_RET_FUNC(sys_mknod, SYS_MKNOD, ARG_TYPE0(STR_T)|ARG_TYPE1(MODE_T_T)|ARG_TYPE2(DEV_T_T));
TRACE_ENT_FUNC(sys_mknodat);
TRACE_RET_FUNC(sys_mknodat, SYS_MKNODAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(MODE_T_T)|ARG_TYPE3(DEV_T_T));
TRACE_ENT_FUNC(sys_memfd_create);
TRACE_RET_FUNC(sys_memfd_create, SYS_MEMFD_CREATE, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_dup);
TRACE_RET_FUNC(sys_dup, SYS_DUP, ARG_TYPE0(INT_T));
TRACE_ENT_FUNC(sys_dup2);
TRACE_RET_FUNC(sys_dup2, SYS_DUP2, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_dup3);
TRACE_RET_FUNC(sys_dup3, SYS_DUP3, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T));
TRACE_ENT_FUNC(sys_fork);
TRACE_RET_FUNC(sys_fork, SYS_FORK, 0);
TRACE_ENT_FUNC(sys_vfork);
TRACE_RET_FUNC(sys_vfork, SYS_VFORK, 0);
TRACE_ENT_FUNC(sys_clone);
TRACE_RET_FUNC(sys_clone, SYS_CLONE, 0);
TRACE_ENT_FUNC(sys_newstat);
TRACE_RET_FUNC(sys_newstat, SYS_STAT, ARG_TYPE0(STR_T));
TRACE_ENT_FUNC(sys_newlstat);
TRACE_RET_FUNC(sys_newlstat, SYS_LSTAT, ARG_TYPE0(STR_T));
TRACE_ENT_FUNC(sys_newfstat);
TRACE_RET_FUNC(sys_newfstat, SYS_FSTAT, ARG_TYPE0(INT_T));
TRACE_ENT_FUNC(sys_socket);
TRACE_RET_FUNC(sys_socket, SYS_SOCKET, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T));
TRACE_ENT_FUNC(sys_close);
TRACE_RET_FUNC(sys_close, SYS_CLOSE, ARG_TYPE0(INT_T));
TRACE_ENT_FUNC(sys_ioctl);
TRACE_RET_FUNC(sys_ioctl, SYS_IOCTL, ARG_TYPE0(INT_T)|ARG_TYPE1(LONG_T));
TRACE_ENT_FUNC(sys_access);
TRACE_RET_FUNC(sys_access, SYS_ACCESS, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_faccessat);
TRACE_RET_FUNC(sys_faccessat, SYS_FACCESSAT, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T));
TRACE_ENT_FUNC(sys_kill);
TRACE_RET_FUNC(sys_kill, SYS_KILL, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_listen);
TRACE_RET_FUNC(sys_listen, SYS_LISTEN, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_connect);
TRACE_RET_FUNC(sys_connect, SYS_CONNECT, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_FUNC(sys_accept);
TRACE_RET_FUNC(sys_accept, SYS_ACCEPT, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_FUNC(sys_accept4);
TRACE_RET_FUNC(sys_accept4, SYS_ACCEPT4, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_FUNC(sys_bind);
TRACE_RET_FUNC(sys_bind, SYS_BIND, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_FUNC(sys_getsockname);
TRACE_RET_FUNC(sys_getsockname, SYS_GETSOCKNAME, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T));
TRACE_ENT_FUNC(sys_prctl);
TRACE_RET_FUNC(sys_prctl, SYS_PRCTL, ARG_TYPE0(INT_T)|ARG_TYPE1(LONG_T)|ARG_TYPE2(LONG_T)|ARG_TYPE3(LONG_T)|ARG_TYPE4(LONG_T));
TRACE_ENT_FUNC(sys_ptrace);
TRACE_RET_FUNC(sys_ptrace, SYS_PTRACE, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(POINTER_T)|ARG_TYPE3(POINTER_T));
TRACE_ENT_FUNC(sys_process_vm_writev);
TRACE_RET_FUNC(sys_process_vm_writev, SYS_PROCESS_VM_WRITEV, ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T)|ARG_TYPE2(LONG_T)|ARG_TYPE3(POINTER_T)|ARG_TYPE4(LONG_T)|ARG_TYPE5(LONG_T));
TRACE_ENT_FUNC(sys_process_vm_readv);
TRACE_RET_FUNC(sys_process_vm_readv, SYS_PROCESS_VM_READV, ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T)|ARG_TYPE2(LONG_T)|ARG_TYPE3(POINTER_T)|ARG_TYPE4(LONG_T)|ARG_TYPE5(LONG_T));
TRACE_ENT_FUNC(sys_init_module);
TRACE_RET_FUNC(sys_init_module, SYS_INIT_MODULE, ARG_TYPE0(POINTER_T)|ARG_TYPE1(LONG_T)|ARG_TYPE2(STR_T));
TRACE_ENT_FUNC(sys_finit_module);
TRACE_RET_FUNC(sys_finit_module, SYS_FINIT_MODULE, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T));
TRACE_ENT_FUNC(sys_delete_module);
TRACE_RET_FUNC(sys_delete_module, SYS_DELETE_MODULE, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T));
TRACE_ENT_FUNC(sys_symlink);
TRACE_RET_FUNC(sys_symlink, SYS_SYMLINK, ARG_TYPE0(STR_T)|ARG_TYPE1(STR_T));
TRACE_ENT_FUNC(sys_symlinkat);
TRACE_RET_FUNC(sys_symlinkat, SYS_SYMLINKAT, ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(STR_T));
TRACE_ENT_FUNC(sys_getdents);
TRACE_RET_FUNC(sys_getdents, SYS_GETDENTS, ARG_TYPE0(INT_T));
TRACE_ENT_FUNC(sys_getdents64);
TRACE_RET_FUNC(sys_getdents64, SYS_GETDENTS64, ARG_TYPE0(INT_T));


// Note: race condition may occur if a malicious user changes the arguments concurrently
// consider using security_bprm_set_creds instead
int trace_sys_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    context_t context = {};

    if (add_pid_ns_if_needed() == 0)
        return 0;

    if (init_context(&context) || init_event())
        return 0;

    context.eventid = SYS_EXECVE;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_to_submit_buf((void*)&context, sizeof(context_t));
    int type = EVENT_ARG;
    save_to_submit_buf((void*)&type, sizeof(int));

    save_str_to_buf((void *)filename);

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
    events_perf_submit(ctx);
    return 0;
}

int trace_ret_sys_execve(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    context_t context = {};

    if (init_context(&context) || init_event())
        return 0;

    context.eventid = SYS_EXECVE;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    int type = EVENT_RET;

    save_to_submit_buf((void*)&context, sizeof(context_t));
    save_to_submit_buf((void*)&type, sizeof(int));
    events_perf_submit(ctx);
    return 0;
}

int trace_sys_execveat(struct pt_regs *ctx,
    const int dirfd,
    const char __user *pathname,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp,
    const int flags)
{
    context_t context = {};

    if (add_pid_ns_if_needed() == 0)
        return 0;

    if (init_context(&context) || init_event())
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_to_submit_buf((void*)&context, sizeof(context_t));
    int type = EVENT_ARG;
    save_to_submit_buf((void*)&type, sizeof(int));
    save_to_submit_buf((void*)&dirfd, sizeof(int));

    save_str_to_buf((void *)pathname);

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
    save_to_submit_buf((void*)&flags, sizeof(int));
    events_perf_submit(ctx);
    return 0;
}

int trace_ret_sys_execveat(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    context_t context = {};

    if (init_context(&context) || init_event())
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    int type = EVENT_RET;

    save_to_submit_buf((void*)&context, sizeof(context_t));
    save_to_submit_buf((void*)&type, sizeof(int));
    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

int trace_do_exit(struct pt_regs *ctx, long code)
{
    context_t context = {};

    if (init_context(&context) || init_event())
        return 0;

    context.eventid = DO_EXIT;
    context.retval = code;

    remove_pid_ns_if_needed();

    save_to_submit_buf((void*)&context, sizeof(context_t));
    events_perf_submit(ctx);
    return 0;
}

int trace_cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int cap_opt)
{
    int audit;
    context_t context = {};

    if (init_context(&context) || init_event())
        return 0;

    context.eventid = CAP_CAPABLE;

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    save_to_submit_buf((void*)&context, sizeof(context_t));
    save_to_submit_buf((void*)&cap, sizeof(int));
    events_perf_submit(ctx);
    return 0;
};
