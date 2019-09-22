/*
 * Authors:
 * 	Yaniv Agman <yaniv@aquasec.com>
 *
 */

// todo: add missing syscalls
// todo: macro of function which includes entry and exit
// todo: fix problem with execveat - can't see pathname
// todo: save argv_loc array in a map instead of submitting it (to avoid race condition). we can't remove entrance as after execve memory is wiped
// todo: add check for head and tail to avoid overflow!
// todo: execve: handle envp, put argv and envp in a list instead being different param for each arg
// todo: have modification of a new syscall happen in one consolidated struct, that will be used in relevant macro (to avoid updating in several places in file)
// todo: add a "do extra" function inside the macro, so we can also include special cases (e.g. is_capable)
// todo: add support for kernel versions 4.19 onward (see kernel version dependant section below)

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>

#define MAX_STRING_SIZE 4096                                // Choosing this value to be the same as PATH_MAX
#define MAX_STRINGS_IN_BUF 32                               // Each cpu can hold up to MAX_STRINGS_IN_BUF strings
#define STR_BUFSIZE  MAX_STRING_SIZE*MAX_STRINGS_IN_BUF     // Need to be power of 2
#define STR_BUFSIZE_HALF   ((STR_BUFSIZE-1) >> 1)           // Bitmask for ebpf validator - this is why we need STR_BUFSIZE to be power of 2
#define SUBMIT_BUFSIZE  4096                                // Percpu buffer size. Need to be power of 2. Max size possible is (2^17)/log(num_of_cpus)
#define SUBMIT_BUFSIZE_HALF   ((SUBMIT_BUFSIZE-1) >> 1)     // Bitmask for ebpf validator - this is why we need PER_CPU_BUFSIZE to be power of 2

/*==================================== ENUMS =================================*/

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

enum event_id {
    SYS_EXECVE,
    SYS_EXECVEAT,
    SYS_FORK,
    SYS_VFORK,
    SYS_CLONE,
    SYS_OPEN,
    SYS_MMAP,
    SYS_MPROTECT,
    SYS_STAT,
    SYS_FSTAT,
    SYS_LSTAT,
    SYS_MKNOD,
    SYS_MKNODAT,
    SYS_MEMFD_CREATE,
    SYS_DUP,
    SYS_DUP2,
    SYS_DUP3,
    SYS_CLOSE,
    SYS_IOCTL,
    SYS_ACCESS,
    SYS_FACCESSAT,
    SYS_KILL,
    SYS_LISTEN,
    SYS_SOCKET,
    SYS_CONNECT,
    SYS_ACCEPT,
    SYS_ACCEPT4,
    SYS_BIND,
    SYS_GETSOCKNAME,
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

typedef struct execve_info {
    context_t context;
    enum event_type type;
    int argv_loc[MAXARG+1];     // argv location in str_buf
} execve_info_t;

typedef struct execveat_info {
    context_t context;
    enum event_type type;
    int argv_loc[MAXARG+1];     // argv location in str_buf
    int dirfd;
    int flags;
} execveat_info_t;

typedef struct cap_info {
    context_t context;
    int capability;
} cap_info_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct string_buf {
    int head, tail;
    u8 buf[STR_BUFSIZE];
} string_buf_t;

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

/*=================================== MAPS =====================================*/

BPF_HASH(cont_pidns, u32, u32);                     // Save container pid namespaces
BPF_HASH(args_map, u64, args_t);                    // Persist args info between function entry and return
BPF_ARRAY(str_buf, string_buf_t, 32);               // buffer to read strings into. Not using percpu array as it caused insufficient memory with large buffer size.
BPF_PERCPU_ARRAY(submission_buf, submit_buf_t, 1);  // Buffer used for perf_submit

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

static __always_inline submit_buf_t * init_submit_buf()
{
    int idx = 0;
    // get per-cpu buffer
    submit_buf_t *submit_p = submission_buf.lookup(&idx);
    if (submit_p) {
        submit_p->off = 0;
        return submit_p;
    }

    return NULL;
}

static __always_inline int save_to_submit_buf(void *ptr, int size)
{
    int idx = 0;
    // get per-cpu buffer
    submit_buf_t *submit_p = submission_buf.lookup(&idx);
    if (submit_p) {
        if (submit_p->off > SUBMIT_BUFSIZE_HALF)
            // not enough space - return
            return 0;

        // read into buffer
        int rc = bpf_probe_read((void **)&(submit_p->buf[submit_p->off & SUBMIT_BUFSIZE_HALF]), size, ptr);
        if (rc == 0) {
            submit_p->off += size;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_str_to_buf(void *ptr, int *arg)
{
    int key = bpf_get_smp_processor_id();
    string_buf_t *str_p = str_buf.lookup(&key);
    if (str_p) {
        if (str_p->tail > STR_BUFSIZE_HALF)
            // not enough space - return to ring buffer start (ebpf validator forces bounds check)
            str_p->tail = 0;

        // read into buffer
        int sz = bpf_probe_read_str((void **)&(str_p->buf[str_p->tail & STR_BUFSIZE_HALF]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
            // save offset and size so userspace will know how many bytes to read
            int str_loc = (str_p->tail << 16) + sz;
            if (arg)
                // save str_loc to given arg
                *arg = str_loc;
            else
                // submit str_loc to the submit buffer
                save_to_submit_buf((void*)&str_loc, sizeof(int));
            str_p->tail += sz;
            return 1;
        }
    }

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx, void *data, u32 data_size)
{
    /* satisfy validator by setting buffer bounds */
    int size = ((data_size - 1) & SUBMIT_BUFSIZE_HALF) + 1;
    return events.perf_submit(ctx, data, size);
}

static __always_inline int save_argv(struct pt_regs *ctx, void *ptr, int *argv_loc)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return save_str_to_buf((void *)(argp), argv_loc);
    }
    return 0;
}

static __always_inline int is_container()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    return lookup_pid_ns(task);
}

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

static __always_inline int prepare_data(int types)
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
            save_str_to_buf((void *)args.args[i], NULL);
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
    submit_buf_t *submit_p = init_submit_buf();                         \
    if (!submit_p)                                                      \
        return -1;                                                      \
                                                                        \
    if (init_context(&context))                                         \
        return 0;                                                       \
                                                                        \
    context.eventid = id;                                               \
    context.retval = PT_REGS_RC(ctx);                                   \
    save_to_submit_buf((void*)&context, sizeof(context_t));             \
    prepare_data(types);                                                \
                                                                        \
    events_perf_submit(ctx, submit_p->buf, submit_p->off);              \
    return 0;                                                           \
}

/*============================== SYSCALL HOOKS ==============================*/

// Note: race condition may occur if a malicious user changes the arguments concurrently
// consider using security_file_open instead
TRACE_ENT_FUNC(open);
TRACE_RET_FUNC(open, SYS_OPEN, ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T));
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

// Note: race condition may occur if a malicious user changes the arguments concurrently
// consider using security_bprm_set_creds instead
int trace_sys_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    execve_info_t exec_info = {};

    if (add_pid_ns_if_needed() == 0)
        return 0;

    if (init_context(&exec_info.context))
        return 0;

    exec_info.context.eventid = SYS_EXECVE;
    exec_info.type = EVENT_ARG;

    save_str_to_buf((void *)filename, &exec_info.argv_loc[0]);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (save_argv(ctx, (void *)&__argv[i], &exec_info.argv_loc[i]) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    save_str_to_buf((void *)ellipsis, &exec_info.argv_loc[MAXARG]);
out:
    events.perf_submit(ctx, &exec_info, sizeof(execve_info_t));
    return 0;
}

int trace_ret_sys_execve(struct pt_regs *ctx)
{
    execve_info_t info = {};

    if (init_context(&info.context))
        return 0;

    info.context.eventid = SYS_EXECVE;
    info.context.retval = PT_REGS_RC(ctx);
    info.type = EVENT_RET;

    events.perf_submit(ctx, &info, sizeof(execve_info_t));

    return 0;
}

int trace_sys_execveat(struct pt_regs *ctx,
    const int dirfd,
    const char __user *pathname,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp,
    const int flags)
{
    // create data here and pass to submit_arg to save stack space (#555)
    execveat_info_t exec_info = {};

    if (add_pid_ns_if_needed() == 0)
        return 0;

    if (init_context(&exec_info.context))
        return 0;

    exec_info.context.eventid = SYS_EXECVEAT;
    exec_info.type = EVENT_ARG;

    save_args(ctx);

    save_str_to_buf((void *)pathname, &exec_info.argv_loc[0]);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (save_argv(ctx, (void *)&__argv[i], &exec_info.argv_loc[i]) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    save_str_to_buf((void *)ellipsis, &exec_info.argv_loc[MAXARG]);
out:
    events.perf_submit(ctx, &exec_info, sizeof(execveat_info_t));
    return 0;
}

int trace_ret_sys_execveat(struct pt_regs *ctx)
{
    execveat_info_t exec_info = {};
    args_t args = {};

    if (init_context(&exec_info.context))
        return 0;

    if (load_args(&args) != 0)
        return 0;

    exec_info.context.eventid = SYS_EXECVEAT;
    exec_info.context.retval = PT_REGS_RC(ctx);
    exec_info.type = EVENT_RET;
    exec_info.dirfd = (int)args.args[0];
    exec_info.flags = (int)args.args[4];

    events.perf_submit(ctx, &exec_info, sizeof(execveat_info_t));
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

int trace_do_exit(struct pt_regs *ctx, long code)
{
    context_t context = {};

    if (init_context(&context))
        return 0;

    context.eventid = DO_EXIT;
    context.retval = code;

    remove_pid_ns_if_needed();

    events.perf_submit(ctx, &context, sizeof(context_t));
    return 0;
}

int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int cap_opt)
{
    int audit;
    cap_info_t cap_info = {};

    if (init_context(&cap_info.context))
        return 0;

    cap_info.context.eventid = CAP_CAPABLE;
    cap_info.capability = cap;

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    events.perf_submit(ctx, &cap_info, sizeof(cap_info_t));
    return 0;
};
