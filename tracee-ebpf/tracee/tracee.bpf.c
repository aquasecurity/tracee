// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 */
#include <linux/types.h>
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/uio.h>
#include <uapi/linux/un.h>
#include <uapi/linux/utsname.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/ipc_namespace.h>
#include <net/net_namespace.h>
#include <linux/utsname.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>
#include <linux/kconfig.h>
#include <linux/version.h>

#undef container_of
//#include "bpf_core_read.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx)  ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096          // Choosing this value to be the same as PATH_MAX
#define MAX_BYTES_ARR_SIZE  4096          // Max size of bytes array, arbitrarily chosen
#define MAX_STR_ARR_ELEM    40            // String array elements number should be bounded due to instructions limit
#define MAX_PATH_PREF_SIZE  64            // Max path prefix should be bounded due to instructions limit
#define MAX_STACK_ADDRESSES 1024          // Max amount of different stack trace addresses to buffer in the Map
#define MAX_STACK_DEPTH     20            // Max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE 16            // Max string filter size should be bounded to the size of the compared values (comm, uts)
#define FILE_MAGIC_HDR_SIZE 16            // Number of bytes to save from a file's header (for magic_write event)
#define FILE_MAGIC_MASK     15            // Mask used to pass verifier when submitting magic_write event bytes

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
#define BYTES_T       14UL
#define TYPE_MAX      255UL

#define TAG_NONE           0UL

#if defined(bpf_target_x86)
#define SYS_OPEN              2
#define SYS_MMAP              9
#define SYS_MPROTECT          10
#define SYS_RT_SIGRETURN      15
#define SYS_CLONE             56
#define SYS_FORK              57
#define SYS_VFORK             58
#define SYS_EXECVE            59
#define SYS_EXIT              60
#define SYS_EXIT_GROUP        231
#define SYS_OPENAT            257
#define SYS_EXECVEAT          322
#elif defined(bpf_target_arm64)
#define SYS_OPEN              1000 // undefined in arm64
#define SYS_MMAP              222
#define SYS_MPROTECT          226
#define SYS_RT_SIGRETURN      139
#define SYS_CLONE             220
#define SYS_FORK              1000 // undefined in arm64
#define SYS_VFORK             1000 // undefined in arm64
#define SYS_EXECVE            221
#define SYS_EXIT              93
#define SYS_EXIT_GROUP        94
#define SYS_OPENAT            56
#define SYS_EXECVEAT          281
#endif

#define RAW_SYS_ENTER         1000
#define RAW_SYS_EXIT          1001
#define DO_EXIT               1002
#define CAP_CAPABLE           1003
#define SECURITY_BPRM_CHECK   1004
#define SECURITY_FILE_OPEN    1005
#define SECURITY_INODE_UNLINK 1006
#define VFS_WRITE             1007
#define VFS_WRITEV            1008
#define MEM_PROT_ALERT        1009
#define SCHED_PROCESS_EXIT    1010
#define COMMIT_CREDS          1011
#define SWITCH_TASK_NS        1012
#define MAGIC_WRITE           1013
#define MAX_EVENT_ID          1014

#define CONFIG_SHOW_SYSCALL         1
#define CONFIG_EXEC_ENV             2
#define CONFIG_CAPTURE_FILES        3
#define CONFIG_EXTRACT_DYN_CODE     4
#define CONFIG_TRACEE_PID           5
#define CONFIG_CAPTURE_STACK_TRACES 6
#define CONFIG_UID_FILTER           7
#define CONFIG_MNT_NS_FILTER        8
#define CONFIG_PID_NS_FILTER        9
#define CONFIG_UTS_NS_FILTER        10
#define CONFIG_COMM_FILTER          11
#define CONFIG_PID_FILTER           12
#define CONFIG_CONT_FILTER          13
#define CONFIG_FOLLOW_FILTER        14
#define CONFIG_NEW_PID_FILTER       15
#define CONFIG_NEW_CONT_FILTER      16

// get_config(CONFIG_XXX_FILTER) returns 0 if not enabled
#define FILTER_IN  1
#define FILTER_OUT 2

#define UID_LESS      0
#define UID_GREATER   1
#define PID_LESS      2
#define PID_GREATER   3
#define MNTNS_LESS    4
#define MNTNS_GREATER 5
#define PIDNS_LESS    6
#define PIDNS_GREATER 7

#define LESS_NOT_SET    0
#define GREATER_NOT_SET ULLONG_MAX

#define DEV_NULL_STR    0

#define KERNEL_CONFIG_BPF                       1
#define KERNEL_CONFIG_BPF_SYSCALL               2
#define KERNEL_CONFIG_HAVE_EBPF_JIT             3
#define KERNEL_CONFIG_BPF_JIT                   4
#define KERNEL_CONFIG_BPF_JIT_ALWAYS_ON         5
#define KERNEL_CONFIG_CGROUPS                   6
#define KERNEL_CONFIG_CGROUP_BPF                7
#define KERNEL_CONFIG_CGROUP_NET_CLASSID        8
#define KERNEL_CONFIG_SOCK_CGROUP_DATA          9
#define KERNEL_CONFIG_BPF_EVENTS                10
#define KERNEL_CONFIG_KPROBE_EVENTS             11
#define KERNEL_CONFIG_UPROBE_EVENTS             12
#define KERNEL_CONFIG_TRACING                   13
#define KERNEL_CONFIG_FTRACE_SYSCALLS           14
#define KERNEL_CONFIG_FUNCTION_ERROR_INJECTION  15
#define KERNEL_CONFIG_BPF_KPROBE_OVERRIDE       16
#define KERNEL_CONFIG_NET                       17
#define KERNEL_CONFIG_XDP_SOCKETS               18
#define KERNEL_CONFIG_LWTUNNEL_BPF              19
#define KERNEL_CONFIG_NET_ACT_BPF               20
#define KERNEL_CONFIG_NET_CLS_BPF               21
#define KERNEL_CONFIG_NET_CLS_ACT               22
#define KERNEL_CONFIG_NET_SCH_INGRESS           23
#define KERNEL_CONFIG_XFRM                      24
#define KERNEL_CONFIG_IP_ROUTE_CLASSID          25
#define KERNEL_CONFIG_IPV6_SEG6_BPF             26
#define KERNEL_CONFIG_BPF_LIRC_MODE2            27
#define KERNEL_CONFIG_BPF_STREAM_PARSER         28
#define KERNEL_CONFIG_NETFILTER_XT_MATCH_BPF    29
#define KERNEL_CONFIG_BPFILTER                  30
#define KERNEL_CONFIG_BPFILTER_UMH              31
#define KERNEL_CONFIG_TEST_BPF                  32
#define KERNEL_CONFIG_HZ                        33
#define KERNEL_CONFIG_DEBUG_INFO_BTF            34
#define KERNEL_CONFIG_DEBUG_INFO_BTF_MODULES    35
#define KERNEL_CONFIG_BPF_LSM                   36
#define KERNEL_CONFIG_BPF_PRELOAD               37
#define KERNEL_CONFIG_BPF_PRELOAD_UMD           38

#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = _type, \
  .key_size = sizeof(_key_type), \
  .value_size = sizeof(_value_type), \
  .max_entries = _max_entries, \
};

#define BPF_HASH(_name, _key_type, _value_type) \
BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);

#define BPF_ARRAY(_name, _value_type, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries);

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries);

#define BPF_PROG_ARRAY(_name, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries);

#define BPF_PERF_OUTPUT(_name) \
BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
#define BPF_STACK_TRACE(_name, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = BPF_MAP_TYPE_STACK_TRACE, \
  .key_size = sizeof(u32), \
  .value_size = sizeof(size_t) * MAX_STACK_DEPTH, \
  .max_entries = _max_entries, \
};

#ifdef RHEL_RELEASE_CODE
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 0))
#define RHEL_RELEASE_GT_8_0
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#error Minimal required kernel version is 4.18
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
    u32 stack_id;
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

typedef struct string_filter {
    char str[MAX_STR_FILTER_SIZE];
} string_filter_t;

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

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

/*=================================== MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                         // Various configurations
BPF_HASH(chosen_events_map, u32, u32);                  // Events chosen by the user
BPF_HASH(traced_pids_map, u32, u32);                    // Keep track of traced pids
BPF_HASH(new_pids_map, u32, u32);                       // Keep track of the processes of newly executed binaries
BPF_HASH(new_pidns_map, u32, u32);                      // Keep track of new pid namespaces
BPF_HASH(args_map, u64, args_t);                        // Persist args info between function entry and return
BPF_HASH(ret_map, u64, u64);                            // Persist return value to be used in tail calls
BPF_HASH(inequality_filter, u32, u64);                  // Used to filter events by some uint field either by < or >
BPF_HASH(uid_filter, u32, u32);                         // Used to filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, u32);                         // Used to filter events by PID
BPF_HASH(mnt_ns_filter, u64, u32);                      // Used to filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, u32);                      // Used to filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, u32);          // Used to filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, u32);            // Used to filter events by command name
BPF_HASH(bin_args_map, u64, bin_args_t);                // Persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32);                   // Map 32bit syscalls numbers to 64bit syscalls numbers
BPF_HASH(params_types_map, u32, u64);                   // Encoded parameters types for event
BPF_HASH(params_names_map, u32, u64);                   // Encoded parameters names for event
BPF_HASH(kernel_config_map, u32, u32);                  // Kernel configuration
BPF_ARRAY(file_filter, path_filter_t, 3);               // Used to filter vfs_write events
BPF_ARRAY(string_store, path_filter_t, 1);              // Store strings from userspace
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);             // Percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // Holds offsets to bufs respectively
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);              // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);          // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);           // Used to store programs for tail calls
BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);  // Used to store stack traces

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                            // Events submission
BPF_PERF_OUTPUT(file_writes);                       // File writes events submission

/*================== KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

static __always_inline u32 kernel_config_option_enabled(u32 key) {
    u32 *set = bpf_map_lookup_elem(&kernel_config_map, &key);
    if (set == NULL) {
        return false;
    }
    return *set;
}

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    return READ_KERN(READ_KERN(ns->mnt_ns)->ns.inum);
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    return READ_KERN(READ_KERN(ns->pid_ns_for_children)->ns.inum);
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    return READ_KERN(READ_KERN(ns->uts_ns)->ns.inum);
}

static __always_inline u32 get_ipc_ns_id(struct nsproxy *ns)
{
    return READ_KERN(READ_KERN(ns->ipc_ns)->ns.inum);
}

static __always_inline u32 get_net_ns_id(struct nsproxy *ns)
{
    return READ_KERN(READ_KERN(ns->net_ns)->ns.inum);
}

static __always_inline u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    return READ_KERN(READ_KERN(ns->cgroup_ns)->ns.inum);
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ipc_ns_id(struct task_struct *task)
{
    return get_ipc_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_net_ns_id(struct task_struct *task)
{
    return get_net_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_cgroup_ns_id(struct task_struct *task)
{
    return get_cgroup_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->level);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
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
#if defined(bpf_target_x86)
    return READ_KERN(task->thread_info.status) & TS_COMPAT;
#else
    return false;
#endif
}

static __always_inline bool is_arm64_compat(struct task_struct *task)
{
#if defined(bpf_target_arm64)
    return READ_KERN(task->thread_info.flags) & _TIF_32BIT;
#else
    return false;
#endif
}

static __always_inline bool is_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return is_x86_compat(task);
#elif defined(bpf_target_arm64)
    return is_arm64_compat(task);
#else
    return false;
#endif
}

#if defined(bpf_target_x86)
static __always_inline struct pt_regs* get_task_pt_regs(struct task_struct *task)
{
    void* __ptr = READ_KERN(task->stack) + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *)__ptr) - 1;
}
#endif

static __always_inline int get_syscall_ev_id_from_regs()
{
#if defined(bpf_target_x86)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pt_regs *real_ctx = get_task_pt_regs(task);
    int syscall_nr = READ_KERN(real_ctx->orig_ax);

    if (is_x86_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls (which also represent the event ids)
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &syscall_nr);
        if (id_64 == 0)
            return -1;

        syscall_nr = *id_64;
    }

    return syscall_nr;
#else
    return 0;
#endif
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
    return container_of(mnt, struct mount, mnt);
}

/*============================== HELPER FUNCTIONS ==============================*/

static __inline int has_prefix(char *prefix, char *str, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    // prefix is too long
    return 0;
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

    // Clean Stack Trace ID
    context->stack_id = 0;

    return 0;
}

static __always_inline int get_config(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

// returns 1 if you should trace based on uid, 0 if not
static __always_inline int uint_filter_matches(int filter_config, void *filter_map, u64 key, u32 less_idx, u32 greater_idx)
{
    int config = get_config(filter_config);
    if (!config)
        return 1;

    u8* equality = bpf_map_lookup_elem(filter_map, &key);
    if (equality != NULL) {
        return *equality;
    }

    if (config == FILTER_IN)
        return 0;

    u64* lessThan = bpf_map_lookup_elem(&inequality_filter, &less_idx);
    if (lessThan == NULL)
        return 1;

    if ((*lessThan != LESS_NOT_SET) && (key >= *lessThan)) {
        return 0;
    }

    u64* greaterThan = bpf_map_lookup_elem(&inequality_filter, &greater_idx);
    if (greaterThan == NULL)
        return 1;

    if ((*greaterThan != GREATER_NOT_SET) && (key <= *greaterThan)) {
        return 0;
    }

    return 1;
}

static __always_inline int equality_filter_matches(int filter_config, void *filter_map, void *key)
{
    int config = get_config(filter_config);
    if (!config)
        return 1;

    u32* equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL) {
        return *equality;
    }

    if (config == FILTER_IN)
        return 0;

    return 1;
}

static __always_inline int bool_filter_matches(int filter_config, bool val)
{
    int config = get_config(filter_config);
    if (!config)
        return 1;

    if ((config == FILTER_IN) && val){
        return 1;
    }

    if ((config == FILTER_OUT) && !val) {
        return 1;
    }

    return 0;
}

static __always_inline int should_trace()
{
    context_t context = {};
    init_context(&context);

    if (get_config(CONFIG_FOLLOW_FILTER)) {
        if (bpf_map_lookup_elem(&traced_pids_map, &context.host_tid) != 0)
            // If the process is already in the traced_pids_map and follow was chosen, don't check the other filters
            return 1;
    }

    bool is_new_pid = bpf_map_lookup_elem(&new_pids_map, &context.host_tid) != 0;
    if (!bool_filter_matches(CONFIG_NEW_PID_FILTER, is_new_pid))
    {
        return 0;
    }

    bool is_new_container = bpf_map_lookup_elem(&new_pidns_map, &context.pid_id) != 0;
    if (!bool_filter_matches(CONFIG_NEW_CONT_FILTER, is_new_container))
    {
        return 0;
    }

    // Don't monitor self
    if (get_config(CONFIG_TRACEE_PID) == context.host_pid) {
        return 0;
    }

    if (!uint_filter_matches(CONFIG_UID_FILTER, &uid_filter, context.uid, UID_LESS, UID_GREATER))
    {
        return 0; 
    }

    if (!uint_filter_matches(CONFIG_MNT_NS_FILTER, &mnt_ns_filter, context.mnt_id, MNTNS_LESS, MNTNS_GREATER))
    {
        return 0;
    }

    if (!uint_filter_matches(CONFIG_PID_NS_FILTER, &pid_ns_filter, context.pid_id, PIDNS_LESS, PIDNS_GREATER))
    {
        return 0;
    }

    if (!uint_filter_matches(CONFIG_PID_FILTER, &pid_filter, context.host_tid, PID_LESS, PID_GREATER))
    {
        return 0;
    }

    if (!equality_filter_matches(CONFIG_UTS_NS_FILTER, &uts_ns_filter, &context.uts_name))
    {
        return 0;
    }

    if (!equality_filter_matches(CONFIG_COMM_FILTER, &comm_filter, &context.comm))
    {
        return 0;
    }
    // TODO: after we move to minimal kernel 4.18, we can check for container by cgroupid != host cgroupid
    bool is_container = context.tid != context.host_tid;
    if (!bool_filter_matches(CONFIG_CONT_FILTER, is_container))
    {
        return 0;
    }

    // We passed all filters successfully
    return 1;
}

static __always_inline int event_chosen(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&chosen_events_map, &key);
    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline buf_t* get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
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

static __always_inline context_t init_and_save_context(void* ctx, buf_t *submit_p, u32 id, u8 argnum, long ret)
{
    context_t context = {};
    init_context(&context);
    context.eventid = id;
    context.argnum = argnum;
    context.retval = ret;

    // Get Stack trace
    if (get_config(CONFIG_CAPTURE_STACK_TRACES)) {
        int stack_id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            context.stack_id = stack_id;
        }
    }

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

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }
    *off += 1;

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

static __always_inline int save_bytes_to_buf(buf_t *submit_p, void *ptr, u32 size, u8 tag)
{
    if (size == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = BYTES_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);

    *off += 1;

    // Save argument tag
    int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }
    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE - sizeof(int)) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Save size to buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &size);
    if (rc != 0) {
        *off -= 2;
        return 0;
    }
    *off += sizeof(int);

    if (*off > MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE - sizeof(int)) {
        // Satisfy validator for probe read
        *off -= (2 + sizeof(int));
        return 0;
    }

    // Read bytes into buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), size & (MAX_BYTES_ARR_SIZE-1), ptr);
    if (rc == 0) {
        *off += size;
        return 1;
    }

    *off -= (2 + sizeof(int));
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
        if (off <= buf_off) { // verify no wrap occured
            len = len & ((MAX_PERCPU_BUFSIZE >> 1)-1);
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
        }
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

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
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

static __always_inline int save_dentry_path_to_str_buf(buf_t *string_p, struct dentry* dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    #pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 30; i++) {
        struct dentry *d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        unsigned int len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occured
            len = len & ((MAX_PERCPU_BUFSIZE >> 1)-1);
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
        }
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

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        struct qstr d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
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
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, size);
}

static __always_inline int save_args(args_t *args, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&args_map, &id, args, BPF_ANY);

    return 0;
}

static __always_inline int save_args_from_regs(struct pt_regs *ctx, u32 event_id, bool is_syscall)
{
    args_t args = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_x86_compat(task) && is_syscall) {
#if defined(bpf_target_x86)
        args.args[0] = ctx->bx;
        args.args[1] = ctx->cx;
        args.args[2] = ctx->dx;
        args.args[3] = ctx->si;
        args.args[4] = ctx->di;
        args.args[5] = ctx->bp;
#endif
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

    if (delete)
        bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int del_args(u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int save_retval(u64 retval, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_update_elem(&ret_map, &id, &retval, BPF_ANY);

    return 0;
}

static __always_inline int load_retval(u64 *retval, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    u64 *saved_retval = bpf_map_lookup_elem(&ret_map, &id);
    if (saved_retval == 0) {
        // missed entry or not traced
        return -1;
    }

    *retval = *saved_retval;
    bpf_map_delete_elem(&ret_map, &id);

    return 0;
}

static __always_inline int del_retval(u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_delete_elem(&ret_map, &id);

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
    init_and_save_context(ctx, submit_p, id, argnum, ret);

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
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    args_t args_tmp = {};
    int id = ctx->args[1];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    struct pt_regs regs = {};
    bpf_probe_read(&regs, sizeof(struct pt_regs), (void*)ctx->args[0]);

    if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
        args_tmp.args[0] = regs.bx;
        args_tmp.args[1] = regs.cx;
        args_tmp.args[2] = regs.dx;
        args_tmp.args[3] = regs.si;
        args_tmp.args[4] = regs.di;
        args_tmp.args[5] = regs.bp;
#endif // bpf_target_x86
    } else {
        args_tmp.args[0] = PT_REGS_PARM1(&regs);
        args_tmp.args[1] = PT_REGS_PARM2(&regs);
        args_tmp.args[2] = PT_REGS_PARM3(&regs);
        args_tmp.args[3] = PT_REGS_PARM4(&regs);
        args_tmp.args[4] = PT_REGS_PARM5(&regs);
        args_tmp.args[5] = PT_REGS_PARM6(&regs);
    }
#else // CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    args_tmp.args[0] = ctx->args[0];
    args_tmp.args[1] = ctx->args[1];
    args_tmp.args[2] = ctx->args[2];
    args_tmp.args[3] = ctx->args[3];
    args_tmp.args[4] = ctx->args[4];
    args_tmp.args[5] = ctx->args[5];
#endif // CONFIG_ARCH_HAS_SYSCALL_WRAPPER

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    u32 pid = bpf_get_current_pid_tgid();

    // execve events may add new pids to the traced pids set
    // perform this check before should_trace() so newly executed binaries will be traced
    if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
        if (get_config(CONFIG_NEW_CONT_FILTER)) {
            u32 pid_ns = get_task_pid_ns_id(task);
            if (get_task_ns_pid(task) == 1) {
                // A new container/pod was started (pid 1 in namespace executed) - add pid namespace to map
                bpf_map_update_elem(&new_pidns_map, &pid_ns, &pid_ns, BPF_ANY);
            }
        }
        if (get_config(CONFIG_NEW_PID_FILTER)) {
            bpf_map_update_elem(&new_pids_map, &pid, &pid, BPF_ANY);
        }
    }

    if (!should_trace())
        return 0;

    if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
        // We passed all filters (in should_trace()) - add this pid to traced pids set
        bpf_map_update_elem(&traced_pids_map, &pid, &pid, BPF_ANY);
    }

    if (event_chosen(RAW_SYS_ENTER)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, RAW_SYS_ENTER, 1 /*argnum*/, 0 /*ret*/);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_to_submit_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

    // exit, exit_group and rt_sigreturn syscalls don't return - don't save args for them
    if (id != SYS_EXIT && id != SYS_EXIT_GROUP && id != SYS_RT_SIGRETURN) {
        save_args(&args_tmp, id);
    }

    // call syscall handler, if exists
    // enter tail calls should never delete saved args
    bpf_tail_call(ctx, &sys_enter_tails, id);
    return 0;
}

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long ret)
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = ctx->args[1];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
    int id = READ_KERN(regs->orig_ax);

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
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

    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    if (id == SYS_CLONE || id == SYS_FORK || id == SYS_VFORK) {
        u32 pid = ret;
        bpf_map_update_elem(&traced_pids_map, &pid, &pid, BPF_ANY);
        if (get_config(CONFIG_NEW_PID_FILTER)) {
            bpf_map_update_elem(&new_pids_map, &pid, &pid, BPF_ANY);
        }
    }

    if (event_chosen(RAW_SYS_EXIT)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, RAW_SYS_EXIT, 1 /*argnum*/, ret);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
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
            u64 *saved_types = bpf_map_lookup_elem(&params_types_map, &id);
            u64 *saved_tags = bpf_map_lookup_elem(&params_names_map, &id);
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
    bpf_tail_call(ctx, &sys_exit_tails, id);
    del_retval(id);
    del_args(id);
    return 0;
}

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    args_t args = {};
    u8 argnum = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVE) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVE))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SYS_EXECVE, 2 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_str_to_buf(submit_p, (void *)args.args[0] /*filename*/, DEC_ARG(0, *tags));
    argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[1] /*argv*/, DEC_ARG(1, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[2] /*envp*/, DEC_ARG(2, *tags));
    }

    context.argnum = argnum;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    args_t args = {};
    u8 argnum = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVEAT) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVEAT))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SYS_EXECVEAT, 4 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_to_submit_buf(submit_p, (void*)&args.args[0] /*dirfd*/, sizeof(int), INT_T, DEC_ARG(0, *tags));
    argnum += save_str_to_buf(submit_p, (void *)args.args[1] /*pathname*/, DEC_ARG(1, *tags));
    argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[2] /*argv*/, DEC_ARG(2, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argnum += save_str_arr_to_buf(submit_p, (const char *const *)args.args[3] /*envp*/, DEC_ARG(3, *tags));
    }
    argnum += save_to_submit_buf(submit_p, (void*)&args.args[4] /*flags*/, sizeof(int), INT_T, DEC_ARG(4, *tags));

    context.argnum = argnum;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/

SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
void *ctx
#else
struct bpf_raw_tracepoint_args *ctx
#endif
)
{
    if (!should_trace())
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    // Remove pid from traced_pids_map
    bpf_map_delete_elem(&traced_pids_map, &pid);

    if (get_config(CONFIG_NEW_CONT_FILTER)) {
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();

        u32 pid_ns = get_task_pid_ns_id(task);
        if (get_task_ns_pid(task) == 1) {
            // If pid equals 1 - stop tracing this pid namespace
            bpf_map_delete_elem(&new_pidns_map, &pid_ns);
        }
    }
    if (get_config(CONFIG_NEW_PID_FILTER)) {
        // Remove pid from new_pids_map
        bpf_map_delete_elem(&new_pids_map, &pid);
    }

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    init_and_save_context(ctx, submit_p, SCHED_PROCESS_EXIT, 0, 0);

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    long code = PT_REGS_PARM1(ctx);

    init_and_save_context(ctx, submit_p, DO_EXIT, 0, code);

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_BPRM_CHECK, 3 /*argnum*/, 0 /*ret*/);

    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
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

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(2, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_FILE_OPEN, 4 /*argnum*/, 0 /*ret*/);

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
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

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
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

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_INODE_UNLINK, 1 /*argnum*/, 0 /*ret*/);

    //struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_dentry_path_to_str_buf(string_p, dentry);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    u8 argnum = 0;
    context_t context = init_and_save_context(ctx, submit_p, COMMIT_CREDS, 2 /*argnum*/, 0 /*ret*/);

    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *old = (struct cred *)READ_KERN(task->real_cred);

    kuid_t old_euid = READ_KERN(old->euid);
    kuid_t new_euid = READ_KERN(new->euid);
    kgid_t old_egid = READ_KERN(old->egid);
    kgid_t new_egid = READ_KERN(new->egid);
    kuid_t old_fsuid = READ_KERN(old->fsuid);
    kuid_t new_fsuid = READ_KERN(new->fsuid);
    kernel_cap_t old_cap_eff = READ_KERN(old->cap_effective);
    kernel_cap_t new_cap_eff = READ_KERN(new->cap_effective);

    // Currently (2021), there are ~40 capabilities in the Linux kernel which are stored in a u32 array of length 2.
    // This might change in the (not so near) future as more capabilities will be added.
    // For now, we use u64 to store this array in one piece
    u64 old_cap_eff_arr = old_cap_eff.cap[1];
    old_cap_eff_arr = (old_cap_eff_arr << 32) + old_cap_eff.cap[0];
    u64 new_cap_eff_arr = new_cap_eff.cap[1];
    new_cap_eff_arr = (new_cap_eff_arr << 32) + new_cap_eff.cap[0];

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    if (old_euid.val != new_euid.val) {
        argnum += save_to_submit_buf(submit_p, (void*)&old_euid.val, sizeof(int), INT_T, DEC_ARG(0, *tags));
        argnum += save_to_submit_buf(submit_p, (void*)&new_euid.val, sizeof(int), INT_T, DEC_ARG(1, *tags));
    }

    if (old_egid.val != new_egid.val) {
        argnum += save_to_submit_buf(submit_p, (void*)&old_egid.val, sizeof(int), INT_T, DEC_ARG(2, *tags));
        argnum += save_to_submit_buf(submit_p, (void*)&new_egid.val, sizeof(int), INT_T, DEC_ARG(3, *tags));
    }

    if (old_fsuid.val != new_fsuid.val) {
        argnum += save_to_submit_buf(submit_p, (void*)&old_fsuid.val, sizeof(int), INT_T, DEC_ARG(4, *tags));
        argnum += save_to_submit_buf(submit_p, (void*)&new_fsuid.val, sizeof(int), INT_T, DEC_ARG(5, *tags));
    }

    if (old_cap_eff_arr != new_cap_eff_arr) {
        argnum += save_to_submit_buf(submit_p, (void*)&old_cap_eff_arr, sizeof(unsigned long), ULONG_T, DEC_ARG(6, *tags));
        argnum += save_to_submit_buf(submit_p, (void*)&new_cap_eff_arr, sizeof(unsigned long), ULONG_T, DEC_ARG(7, *tags));
    }

    if (argnum) {
        context.argnum = argnum;
        save_context_to_buf(submit_p, (void*)&context);
        events_perf_submit(ctx);
    }

    return 0;
}

SEC("kprobe/switch_task_namespaces")
int BPF_KPROBE(trace_switch_task_namespaces)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    u8 argnum = 0;
    context_t context = init_and_save_context(ctx, submit_p, SWITCH_TASK_NS, 1 /*argnum*/, 0 /*ret*/);

    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct nsproxy *new = (struct nsproxy *)PT_REGS_PARM2(ctx);

    if (!new)
        return 0;

    pid_t pid = READ_KERN(task->pid);
    u32 old_mnt = get_task_mnt_ns_id(task);
    u32 new_mnt = get_mnt_ns_id(new);
    u32 old_pid = get_task_pid_ns_id(task);
    u32 new_pid = get_pid_ns_id(new);
    u32 old_uts = get_task_uts_ns_id(task);
    u32 new_uts = get_uts_ns_id(new);
    u32 old_ipc = get_task_ipc_ns_id(task);
    u32 new_ipc = get_ipc_ns_id(new);
    u32 old_net = get_task_net_ns_id(task);
    u32 new_net = get_net_ns_id(new);
    u32 old_cgroup = get_task_cgroup_ns_id(task);
    u32 new_cgroup = get_cgroup_ns_id(new);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_to_submit_buf(submit_p, (void*)&pid, sizeof(int), INT_T, DEC_ARG(0, *tags));

    if (old_mnt != new_mnt) {
        argnum += save_to_submit_buf(submit_p, (void*)&new_mnt, sizeof(u32), UINT_T, DEC_ARG(1, *tags));
    }

    if (old_pid != new_pid) {
        argnum += save_to_submit_buf(submit_p, (void*)&new_pid, sizeof(u32), UINT_T, DEC_ARG(2, *tags));
    }

    if (old_uts != new_uts) {
        argnum += save_to_submit_buf(submit_p, (void*)&new_uts, sizeof(u32), UINT_T, DEC_ARG(3, *tags));
    }

    if (old_ipc != new_ipc) {
        argnum += save_to_submit_buf(submit_p, (void*)&new_ipc, sizeof(u32), UINT_T, DEC_ARG(4, *tags));
    }

    if (old_net != new_net) {
        argnum += save_to_submit_buf(submit_p, (void*)&new_net, sizeof(u32), UINT_T, DEC_ARG(5, *tags));
    }

    if (old_cgroup != new_cgroup) {
        argnum += save_to_submit_buf(submit_p, (void*)&new_cgroup, sizeof(u32), UINT_T, DEC_ARG(6, *tags));
    }

    if (argnum > 1) {
        context.argnum = argnum;
        save_context_to_buf(submit_p, (void*)&context);
        events_perf_submit(ctx);
    }

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    int audit;

    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, CAP_CAPABLE, 1 /*argnum*/, 0 /*ret*/);

    //const struct cred *cred = (const struct cred *)PT_REGS_PARM1(ctx);
    //struct user_namespace *targ_ns = (struct user_namespace *)PT_REGS_PARM2(ctx);
    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
  #else
    audit = cap_opt;
  #endif

    if (audit == 0)
        return 0;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
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

SEC("kprobe/send_bin")
int BPF_KPROBE(send_bin)
{
    // Note: sending the data to the userspace have the following constraints:
    // 1. We need a buffer that we know it's exact size (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data can be overriden if userspace doesn't consume it fast enough

    int i = 0;
    unsigned int chunk_size;
    u64 id = bpf_get_current_pid_tgid();

    bin_args_t *bin_args = bpf_map_lookup_elem(&bin_args_map, &id);
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
            bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
        }
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    buf_t *file_buf_p = get_buf(FILE_BUF_IDX);
    if (file_buf_p == NULL) {
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

#define F_SEND_TYPE   0
#define F_MNT_NS      (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF    (F_MNT_NS + sizeof(u32))
#define F_SZ_OFF      (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF     (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF   (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE  (MAX_PERCPU_BUFSIZE >> 1)

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

        bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, F_CHUNK_OFF+F_CHUNK_SIZE);
    }

    chunk_size = bin_args->full_size - i*F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        // Handle the rest of the write recursively
        bin_args->full_size = chunk_size;
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    // Save last chunk
    chunk_size = chunk_size & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
    bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
    bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

    // Satisfy validator by setting buffer bounds
    int size = (F_CHUNK_OFF+chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
    bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, size);

    // We finished writing an element of the vector - continue to next element
    bin_args->iov_idx++;
    if (bin_args->iov_idx < bin_args->iov_len) {
        // Handle the rest of the write recursively
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
        bin_args->ptr = io_vec.iov_base;
        bin_args->full_size = io_vec.iov_len;
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    }

    bpf_map_delete_elem(&bin_args_map, &id);
    return 0;
}

static __always_inline int do_vfs_write_writev(struct pt_regs *ctx, u32 event_id, u32 tail_call_id)
{
    args_t saved_args;

    bool delete_args = false;
    if (load_args(&saved_args, delete_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    if (!event_chosen(VFS_WRITE) && !event_chosen(VFS_WRITEV) && !event_chosen(MAGIC_WRITE)) {
        bpf_tail_call(ctx, &prog_array, tail_call_id);
        return 0;
    }

    loff_t start_pos;
    void *ptr;
    struct iovec *vec;
    size_t count;
    unsigned long vlen;

    struct file *file      = (struct file *) saved_args.args[0];

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_file_path_to_str_buf(string_p, file);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    if (event_id == VFS_WRITE) {
        ptr                = (void*)         saved_args.args[1];
        count              = (size_t)        saved_args.args[2];
    } else {
        vec                = (struct iovec*) saved_args.args[1];
        vlen               =                 saved_args.args[2];
    }
    loff_t *pos            = (loff_t*)       saved_args.args[3];

    // Extract device id, inode number, and pos (offset)
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    bool char_dev = (start_pos == 0);
    u32 bytes_written = PT_REGS_RC(ctx);
    u32 header_bytes = FILE_MAGIC_HDR_SIZE;
    if (header_bytes > bytes_written)
        header_bytes = bytes_written;

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= bytes_written;

    if (event_chosen(VFS_WRITE) || event_chosen(VFS_WRITEV)) {
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        init_and_save_context(ctx, submit_p, event_id, 5 /*argnum*/, PT_REGS_RC(ctx));

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &event_id);
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
    }

    // magic_write event checks if the header of some file is changed
    if (event_chosen(MAGIC_WRITE) && !char_dev && (start_pos == 0)) {
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        context_t context = init_and_save_context(ctx, submit_p, MAGIC_WRITE, 2 /*argnum*/, PT_REGS_RC(ctx));

        u8 header[FILE_MAGIC_HDR_SIZE];

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));

        if (event_id == VFS_WRITE) {
            if (header_bytes < FILE_MAGIC_HDR_SIZE)
                bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, ptr);
            else
                bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, ptr);
        }
        else {
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &vec[0]);
            if (header_bytes < FILE_MAGIC_HDR_SIZE)
                bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, io_vec.iov_base);
            else
                bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, io_vec.iov_base);
        }

        save_bytes_to_buf(submit_p, header, header_bytes, DEC_ARG(1, *tags));

        // Submit magic_write event
        events_perf_submit(ctx);
    }

    bpf_tail_call(ctx, &prog_array, tail_call_id);
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
    bool has_filter = false;
    bool filter_match = false;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, event_id, 5 /*argnum*/, PT_REGS_RC(ctx));

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

    // Check if capture write was requested for this path
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        int idx = i;
        path_filter_t *filter_p = bpf_map_lookup_elem(&file_filter, &idx);
        if (filter_p == NULL)
            return -1;

        if (!filter_p->path[0])
            break;

        has_filter = true;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
            break;

        if (has_prefix(filter_p->path, &string_p->buf[*off], MAX_PATH_PREF_SIZE)) {
            filter_match = true;
            break;
        }
    }

    if (has_filter && !filter_match) {
        // There is a filter, but no match
        del_args(event_id);
        return 0;
    }
    // No filter was given, or filter match - continue

    // Extract device id, inode number, mode, and pos (offset)
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    unsigned short i_mode = get_inode_mode_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= PT_REGS_RC(ctx);

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = context.pid;

    int idx = DEV_NULL_STR;
    path_filter_t *stored_str_p = bpf_map_lookup_elem(&string_store, &idx);
    if (stored_str_p == NULL)
        return -1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
        return -1;

    // check for /dev/null
    if (!has_prefix(stored_str_p->path, &string_p->buf[*off], 10))
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
        bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);

        // Send file data
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    }
    return 0;
}

SEC("kprobe/vfs_write")
TRACE_ENT_FUNC(vfs_write, VFS_WRITE);

SEC("kretprobe/vfs_write")
int BPF_KPROBE(trace_ret_vfs_write)
{
    return do_vfs_write_writev(ctx, VFS_WRITE, TAIL_VFS_WRITE);
}

SEC("kretprobe/vfs_write_tail")
int BPF_KPROBE(trace_ret_vfs_write_tail)
{
    return do_vfs_write_writev_tail(ctx, VFS_WRITE);
}

SEC("kprobe/vfs_writev")
TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(trace_ret_vfs_writev)
{
    return do_vfs_write_writev(ctx, VFS_WRITEV, TAIL_VFS_WRITEV);
}

SEC("kretprobe/vfs_writev_tail")
int BPF_KPROBE(trace_ret_vfs_writev_tail)
{
    return do_vfs_write_writev_tail(ctx, VFS_WRITEV);
}

SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_alert)
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

    context_t context = init_and_save_context(ctx, submit_p, MEM_PROT_ALERT, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
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

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_mprotect_alert)
{
    args_t args = {};
    bin_args_t bin_args = {};

    // Arguments will be deleted on raw_syscalls_exit (with mprotect syscall id)
    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_MPROTECT) != 0)
        return 0;

    struct vm_area_struct *vma = (struct vm_area_struct *)PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);
    //unsigned long prot = PT_REGS_PARM3(ctx);

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

    context_t context = init_and_save_context(ctx, submit_p, MEM_PROT_ALERT, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
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
            bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
            bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
