// +build ignore

// Note: This file is licenced differently from the rest of the project
// SPDX-License-Identifier: GPL-2.0
// Copyright (C) Aqua Security inc.

#ifndef CORE
    #include <uapi/linux/magic.h>
    #include <uapi/linux/ptrace.h>
    #include <uapi/linux/in.h>
    #include <uapi/linux/in6.h>
    #include <uapi/linux/uio.h>
    #include <uapi/linux/un.h>
    #include <uapi/linux/utsname.h>
    #include <uapi/linux/stat.h>
    #include <linux/binfmts.h>
    #include <linux/cred.h>
    #include <linux/sched.h>
    #include <linux/signal.h>
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
    #include <linux/fdtable.h>
    #define KBUILD_MODNAME "tracee"
    #include <net/af_unix.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <net/ipv6.h>
    #include <net/tcp_states.h>
    #include <linux/ipv6.h>
    #include <uapi/linux/icmp.h>
    #include <uapi/linux/icmpv6.h>

    #include <uapi/linux/bpf.h>
    #include <linux/bpf.h>
    #include <linux/kconfig.h>
    #include <linux/version.h>

    #include <linux/if_ether.h>
    #include <linux/in.h>
    #include <linux/ip.h>
    #include <linux/ipv6.h>
    #include <linux/pkt_cls.h>
    #include <linux/tcp.h>

#else
    // CO:RE is enabled
    #include <vmlinux.h>
    #include <missing_definitions.h>

#endif

#undef container_of
#include <bpf_core_read.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

#if defined(bpf_target_x86)
    #define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
    #define PT_REGS_PARM6(x) ((x)->regs[5])
#endif

// INTERNAL ----------------------------------------------------------------------------------------

#define MAX_PERCPU_BUFSIZE  (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096      // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE  4096      // max size of bytes array (arbitrarily chosen)
#define MAX_STACK_ADDRESSES 1024      // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH     20        // max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE 16        // bounded to size of the compared values (comm)
#define FILE_MAGIC_HDR_SIZE 32        // magic_write: bytes to save from a file's header
#define FILE_MAGIC_MASK     31        // magic_write: mask used for verifier boundaries
#define NET_SEQ_OPS_SIZE    4         // print_net_seq_ops: struct size
#define MAX_KSYM_NAME_SIZE  64

enum buf_idx_e
{
    SUBMIT_BUF_IDX,
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

enum bin_type_e
{
    SEND_VFS_WRITE = 1,
    SEND_MPROTECT,
    SEND_KERNEL_MODULE,
};

#define SEND_META_SIZE 24

enum mem_prot_alert_e
{
    ALERT_MMAP_W_X = 1,
    ALERT_MPROT_X_ADD,
    ALERT_MPROT_W_ADD,
    ALERT_MPROT_W_REM
};

enum tail_call_id_e
{
    TAIL_VFS_WRITE,
    TAIL_VFS_WRITEV,
    TAIL_SEND_BIN,
    TAIL_SEND_BIN_TP,
    TAIL_KERNEL_WRITE,
    MAX_TAIL_CALL
};

enum argument_type_e
{
    NONE_T = 0UL,
    INT_T,
    UINT_T,
    LONG_T,
    ULONG_T,
    OFF_T_T,
    MODE_T_T,
    DEV_T_T,
    SIZE_T_T,
    POINTER_T,
    STR_T,
    STR_ARR_T,
    SOCKADDR_T,
    BYTES_T,
    U16_T,
    CRED_T,
    INT_ARR_2_T,
    UINT64_ARR_T,
    TYPE_MAX = 255UL
};

#if defined(bpf_target_x86)
    #define SYS_MMAP         9
    #define SYS_MPROTECT     10
    #define SYS_RT_SIGRETURN 15
    #define SYS_EXECVE       59
    #define SYS_EXIT         60
    #define SYS_EXIT_GROUP   231
    #define SYS_EXECVEAT     322
    #define SYSCALL_CONNECT  42
    #define SYSCALL_ACCEPT   43
    #define SYSCALL_ACCEPT4  288
    #define SYSCALL_LISTEN   50
    #define SYSCALL_BIND     49
    #define SYSCALL_SOCKET   41
    #define SYS_DUP          32
    #define SYS_DUP2         33
    #define SYS_DUP3         292
#elif defined(bpf_target_arm64)
    #define SYS_MMAP         222
    #define SYS_MPROTECT     226
    #define SYS_RT_SIGRETURN 139
    #define SYS_EXECVE       221
    #define SYS_EXIT         93
    #define SYS_EXIT_GROUP   94
    #define SYS_EXECVEAT     281
    #define SYSCALL_CONNECT  203
    #define SYSCALL_ACCEPT   202
    #define SYSCALL_ACCEPT4  242
    #define SYSCALL_LISTEN   201
    #define SYSCALL_BIND     200
    #define SYSCALL_SOCKET   198
    #define SYS_DUP          23
    #define SYS_DUP2         1000 // undefined in arm64
    #define SYS_DUP3         24
#endif

enum event_id_e
{
    // Common event IDs
    RAW_SYS_ENTER = 1000,
    RAW_SYS_EXIT,
    SCHED_PROCESS_FORK,
    SCHED_PROCESS_EXEC,
    SCHED_PROCESS_EXIT,
    SCHED_SWITCH,
    DO_EXIT,
    CAP_CAPABLE,
    VFS_WRITE,
    VFS_WRITEV,
    MEM_PROT_ALERT,
    COMMIT_CREDS,
    SWITCH_TASK_NS,
    MAGIC_WRITE,
    CGROUP_ATTACH_TASK,
    CGROUP_MKDIR,
    CGROUP_RMDIR,
    SECURITY_BPRM_CHECK,
    SECURITY_FILE_OPEN,
    SECURITY_INODE_UNLINK,
    SECURITY_SOCKET_CREATE,
    SECURITY_SOCKET_LISTEN,
    SECURITY_SOCKET_CONNECT,
    SECURITY_SOCKET_ACCEPT,
    SECURITY_SOCKET_BIND,
    SECURITY_SB_MOUNT,
    SECURITY_BPF,
    SECURITY_BPF_MAP,
    SECURITY_KERNEL_READ_FILE,
    SECURITY_INODE_MKNOD,
    SECURITY_POST_READ_FILE,
    SECURITY_INODE_SYMLINK,
    SECURITY_MMAP_FILE,
    SECURITY_FILE_MPROTECT,
    SOCKET_DUP,
    HIDDEN_INODES,
    __KERNEL_WRITE,
    PROC_CREATE,
    KPROBE_ATTACH,
    CALL_USERMODE_HELPER,
    DIRTY_PIPE_SPLICE,
    DEBUGFS_CREATE_FILE,
    PRINT_SYSCALL_TABLE,
    DEBUGFS_CREATE_DIR,
    DEVICE_ADD,
    REGISTER_CHRDEV,
    SHARED_OBJECT_LOADED,
    DO_INIT_MODULE,
    SOCKET_ACCEPT,
    LOAD_ELF_PHDRS,
    HOOKED_PROC_FOPS,
    PRINT_NET_SEQ_OPS,
    TASK_RENAME,
    MAX_EVENT_ID,

    // Net events IDs
    NET_PACKET = 4000,
    DNS_REQUEST,
    DNS_RESPONSE,

    // Debug events IDs
    DEBUG_NET_SECURITY_BIND = 5000,
    DEBUG_NET_UDP_SENDMSG,
    DEBUG_NET_UDP_DISCONNECT,
    DEBUG_NET_UDP_DESTROY_SOCK,
    DEBUG_NET_UDPV6_DESTROY_SOCK,
    DEBUG_NET_INET_SOCK_SET_STATE,
    DEBUG_NET_TCP_CONNECT
};

#define CAPTURE_IFACE (1 << 0)
#define TRACE_IFACE   (1 << 1)

#define OPT_SHOW_SYSCALL         (1 << 0)
#define OPT_EXEC_ENV             (1 << 1)
#define OPT_CAPTURE_FILES        (1 << 2)
#define OPT_EXTRACT_DYN_CODE     (1 << 3)
#define OPT_CAPTURE_STACK_TRACES (1 << 4)
#define OPT_DEBUG_NET            (1 << 5)
#define OPT_CAPTURE_MODULES      (1 << 6)
#define OPT_CGROUP_V1            (1 << 7)
#define OPT_PROCESS_INFO         (1 << 8)

#define FILTER_UID_ENABLED       (1 << 0)
#define FILTER_UID_OUT           (1 << 1)
#define FILTER_MNT_NS_ENABLED    (1 << 2)
#define FILTER_MNT_NS_OUT        (1 << 3)
#define FILTER_PID_NS_ENABLED    (1 << 4)
#define FILTER_PID_NS_OUT        (1 << 5)
#define FILTER_UTS_NS_ENABLED    (1 << 6)
#define FILTER_UTS_NS_OUT        (1 << 7)
#define FILTER_COMM_ENABLED      (1 << 8)
#define FILTER_COMM_OUT          (1 << 9)
#define FILTER_PID_ENABLED       (1 << 10)
#define FILTER_PID_OUT           (1 << 11)
#define FILTER_CONT_ENABLED      (1 << 12)
#define FILTER_CONT_OUT          (1 << 13)
#define FILTER_FOLLOW_ENABLED    (1 << 14)
#define FILTER_NEW_PID_ENABLED   (1 << 15)
#define FILTER_NEW_PID_OUT       (1 << 16)
#define FILTER_NEW_CONT_ENABLED  (1 << 17)
#define FILTER_NEW_CONT_OUT      (1 << 18)
#define FILTER_PROC_TREE_ENABLED (1 << 19)
#define FILTER_PROC_TREE_OUT     (1 << 20)
#define FILTER_CGROUP_ID_ENABLED (1 << 21)
#define FILTER_CGROUP_ID_OUT     (1 << 22)

enum filter_options_e
{
    UID_LESS,
    UID_GREATER,
    PID_LESS,
    PID_GREATER,
    MNTNS_LESS,
    MNTNS_GREATER,
    PIDNS_LESS,
    PIDNS_GREATER
};

#define LESS_NOT_SET    0
#define GREATER_NOT_SET ULLONG_MAX

#define DEV_NULL_STR 0

#define CONT_ID_LEN          12
#define CONT_ID_MIN_FULL_LEN 64

enum container_state_e
{
    CONTAINER_EXISTED = 1, // container existed before tracee was started
    CONTAINER_CREATED,     // new cgroup path created
    CONTAINER_STARTED      // a process in the cgroup executed a new binary
};

#define PACKET_MIN_SIZE 40

#ifndef CORE
    #if LINUX_VERSION_CODE <                                                                       \
        KERNEL_VERSION(5, 2, 0) // lower values in old kernels (instr lim is 4096)
        #define MAX_STR_ARR_ELEM      40
        #define MAX_ARGS_STR_ARR_ELEM 15
        #define MAX_PATH_PREF_SIZE    64
        #define MAX_PATH_COMPONENTS   20
        #define MAX_BIN_CHUNKS        110
    #else // complexity limit of 1M verified instructions
        #define MAX_STR_ARR_ELEM      128
        #define MAX_ARGS_STR_ARR_ELEM 128
        #define MAX_PATH_PREF_SIZE    128
        #define MAX_PATH_COMPONENTS   48
        #define MAX_BIN_CHUNKS        256
    #endif
#else                                // CORE
    #define MAX_STR_ARR_ELEM      40 // TODO: turn this into global variables set w/ libbpfgo
    #define MAX_ARGS_STR_ARR_ELEM 15
    #define MAX_PATH_PREF_SIZE    64
    #define MAX_PATH_COMPONENTS   20
    #define MAX_BIN_CHUNKS        110
#endif

#define IOCTL_FETCH_SYSCALLS            (1 << 0) // bit wise flags
#define IOCTL_HOOKED_SEQ_OPS            (1 << 1)
#define NUMBER_OF_SYSCALLS_TO_CHECK_X86 18
#define NUMBER_OF_SYSCALLS_TO_CHECK_ARM 14

#define MAX_CACHED_PATH_SIZE 64

// EBPF KCONFIGS -----------------------------------------------------------------------------------

#ifdef CORE
    #define get_kconfig(x) get_kconfig_val(x)
#else
    #define get_kconfig(x) CONFIG_##x
#endif

#ifdef CORE

enum kconfig_key_e
{
    ARCH_HAS_SYSCALL_WRAPPER = 1000U
};

#else

    #ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
        #define CONFIG_ARCH_HAS_SYSCALL_WRAPPER 0
    #endif

#endif // CORE

// EBPF MACRO HELPERS ------------------------------------------------------------------------------

#ifndef CORE

    #define GET_FIELD_ADDR(field) &field

    #define READ_KERN(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_probe_read((void *) &_val, sizeof(_val), &ptr);                                    \
            _val;                                                                                  \
        })

    #define READ_USER(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_probe_read_user((void *) &_val, sizeof(_val), &ptr);                               \
            _val;                                                                                  \
        })

#else // CORE

    #define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

    #define READ_KERN(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_core_read((void *) &_val, sizeof(_val), &ptr);                                     \
            _val;                                                                                  \
        })

    #define READ_USER(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_core_read_user((void *) &_val, sizeof(_val), &ptr);                                \
            _val;                                                                                  \
        })
#endif

// EBPF MAP MACROS ---------------------------------------------------------------------------------

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                                      \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries)                                  \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

#define BPF_ARRAY(_name, _value_type, _max_entries)                                                \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                                         \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries)                                                        \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name, _max_entries)                                                       \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

// stack traces: the value is 1 big byte array of the stack addresses
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries)                                                       \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

#ifndef CORE
    #ifdef RHEL_RELEASE_CODE
        #if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 0))
            #define RHEL_RELEASE_GT_8_0
        #endif
    #endif
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
        #error Minimal required kernel version is 4.18
    #endif
#endif

// INTERNAL STRUCTS --------------------------------------------------------------------------------

// todo: check network context after this change
typedef struct task_context {
    u64 start_time; // thread's start time
    u64 cgroup_id;
    u32 pid;       // PID as in the userspace term
    u32 tid;       // TID as in the userspace term
    u32 ppid;      // Parent PID as in the userspace term
    u32 host_pid;  // PID in host pid namespace
    u32 host_tid;  // TID in host pid namespace
    u32 host_ppid; // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 padding;
} task_context_t;

typedef struct event_context {
    u64 ts; // Timestamp
    task_context_t task;
    u32 eventid;
    u32 padding;
    s64 retval;
    u32 stack_id;
    u16 processor_id; // The ID of the processor which processed the event
    u8 argnum;
} event_context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct syscall_data {
    uint id;           // Current syscall id
    args_t args;       // Syscall arguments
    unsigned long ts;  // Timestamp of syscall entry
    unsigned long ret; // Syscall ret val. May be used by syscall exit tail calls.
} syscall_data_t;

typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced;  // indicates that syscall_data is valid
    bool recompute_scope; // recompute should_trace (new task/context changed/policy changed)
    bool new_task;        // set if this task was started after tracee. Used with new_pid filter
    bool follow;          // set if this task was traced before. Used with the follow filter
    int should_trace;     // last decision of should_trace()
} task_info_t;

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

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

typedef struct config_entry {
    u32 tracee_pid;
    u32 options;
    u32 filters;
    u32 cgroup_v1_hid;
} config_entry_t;

typedef struct event_data {
    struct task_struct *task;
    event_context_t context;
    task_info_t *task_info;
    void *ctx;
    config_entry_t *config;
    buf_t *submit_p;
    u32 buf_off;
} event_data_t;

// For a good summary about capabilities, see https://lwn.net/Articles/636533/
typedef struct slim_cred {
    uid_t uid;           // real UID of the task
    gid_t gid;           // real GID of the task
    uid_t suid;          // saved UID of the task
    gid_t sgid;          // saved GID of the task
    uid_t euid;          // effective UID of the task
    gid_t egid;          // effective GID of the task
    uid_t fsuid;         // UID for VFS ops
    gid_t fsgid;         // GID for VFS ops
    u32 user_ns;         // User Namespace of the event
    u32 securebits;      // SUID-less security management
    u64 cap_inheritable; // caps our children can inherit
    u64 cap_permitted;   // caps we're permitted
    u64 cap_effective;   // caps we can actually use
    u64 cap_bset;        // capability bounding set
    u64 cap_ambient;     // Ambient capability set
} slim_cred_t;

typedef struct network_connection_v4 {
    u32 local_address;
    u16 local_port;
    u32 remote_address;
    u16 remote_port;
} net_conn_v4_t;

typedef struct network_connection_v6 {
    struct in6_addr local_address;
    u16 local_port;
    struct in6_addr remote_address;
    u16 remote_port;
    u32 flowinfo;
    u32 scope_id;
} net_conn_v6_t;

typedef struct net_id {
    struct in6_addr address;
    u16 port;
    u16 protocol;
} net_id_t;

typedef struct net_packet {
    uint64_t ts;
    u32 event_id;
    u32 host_tid;
    char comm[TASK_COMM_LEN];
    u32 len;
    u32 ifindex;
    struct in6_addr src_addr, dst_addr;
    __be16 src_port, dst_port;
    u8 protocol;
} net_packet_t;

typedef struct net_debug {
    uint64_t ts;
    u32 event_id;
    u32 host_tid;
    char comm[TASK_COMM_LEN];
    struct in6_addr local_addr, remote_addr;
    __be16 local_port, remote_port;
    u8 protocol;
    int old_state;
    int new_state;
    u64 sk_ptr;
} net_debug_t;

typedef struct net_ctx {
    u32 host_tid;
    char comm[TASK_COMM_LEN];
} net_ctx_t;

typedef struct net_ctx_ext {
    u32 host_tid;
    char comm[TASK_COMM_LEN];
    __be16 local_port;
} net_ctx_ext_t;

// version is not size limited - save only first 32 bytes.
// srcversion is not size limited - modpost calculates srcversion with size: 25.
#define MODULE_VERSION_MAX_LENGTH    32
#define MODULE_SRCVERSION_MAX_LENGTH 25

typedef struct kmod_data {
    char name[MODULE_NAME_LEN];
    char version[MODULE_VERSION_MAX_LENGTH];
    char srcversion[MODULE_SRCVERSION_MAX_LENGTH];
    u64 prev;
    u64 next;
} kmod_data_t;

typedef struct file_id {
    char pathname[MAX_CACHED_PATH_SIZE];
    dev_t device;
    unsigned long inode;
} file_id_t;

// KERNEL STRUCTS ----------------------------------------------------------------------------------

#ifndef CORE
struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
    // ...
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

struct kretprobe_instance {
};
typedef int kprobe_opcode_t;
struct kprobe;

typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, unsigned long flags);
typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);

struct kprobe {
    kprobe_opcode_t *addr;
    const char *symbol_name;
    kprobe_pre_handler_t pre_handler;
    kprobe_post_handler_t post_handler;
};

    #define get_type_size(x)            sizeof(x)
    #define get_node_addr(array, index) &array[index]

#endif

// EBPF MAPS DECLARATIONS --------------------------------------------------------------------------

// clang-format off

BPF_HASH(kconfig_map, u32, u32, 10240);                 // kernel config variables
BPF_HASH(interpreter_map, u32, file_id_t, 10240);       // interpreter file used for each process
BPF_HASH(events_to_submit, u32, u32, 4096);             // events chosen by the user
BPF_HASH(containers_map, u32, u8, 10240);               // map cgroup id to container status {EXISTED, CREATED, STARTED}
BPF_HASH(args_map, u64, args_t, 1024);                  // persist args between function entry and return
BPF_HASH(inequality_filter, u32, u64, 256);             // filter events by some uint field either by < or >
BPF_HASH(uid_filter, u32, u32, 256);                    // filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, u32, 256);                    // filter events by PID
BPF_HASH(mnt_ns_filter, u64, u32, 256);                 // filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, u32, 256);                 // filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, u32, 256);     // filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, u32, 256);       // filter events by command name
BPF_HASH(cgroup_id_filter, u32, u32, 256);              // filter events by cgroup id
BPF_HASH(bin_args_map, u64, bin_args_t, 256);           // persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32, 1024);             // map 32bit to 64bit syscalls
BPF_HASH(params_types_map, u32, u64, 1024);             // encoded parameters types for event
BPF_HASH(process_tree_map, u32, u32, 10240);            // filter events by the ancestry of the traced process
BPF_LRU_HASH(task_info_map, u32, task_info_t, 10240);   // holds data for every task
BPF_HASH(network_config, u32, int, 1024);               // holds the network config for each iface
BPF_HASH(ksymbols_map, ksym_name_t, u64, 1024);         // holds the addresses of some kernel symbols
BPF_HASH(syscalls_to_check_map, int, u64, 256);         // syscalls to discover
BPF_LRU_HASH(sock_ctx_map, u64, net_ctx_ext_t, 10240);  // socket address to process context
BPF_LRU_HASH(network_map, net_id_t, net_ctx_t, 10240);  // network identifier to process context
BPF_ARRAY(config_map, config_entry_t, 1);               // various configurations
BPF_ARRAY(file_filter, path_filter_t, 3);               // filter vfs_write events
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);             // percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // holds offsets to bufs respectively
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);              // store programs for tail calls
BPF_PROG_ARRAY(prog_array_tp, MAX_TAIL_CALL);           // store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);          // store programs for tail calls
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);           // store programs for tail calls
BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);  // store stack traces
BPF_HASH(module_init_map, u32, kmod_data_t, 256);       // holds module information between

// clang-format on

// EBPF PERF BUFFERS -------------------------------------------------------------------------------

BPF_PERF_OUTPUT(events, 1024);      // events submission
BPF_PERF_OUTPUT(file_writes, 1024); // file writes events submission
BPF_PERF_OUTPUT(net_events, 1024);  // network events submission

// HELPERS: DEVICES --------------------------------------------------------------------------------

static __always_inline const char *get_device_name(struct device *dev)
{
    struct kobject kobj = READ_KERN(dev->kobj);
    return kobj.name;
}

// HELPERS: NAMESPACES -----------------------------------------------------------------------------

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace *mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    struct pid_namespace *pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace *uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

static __always_inline u32 get_ipc_ns_id(struct nsproxy *ns)
{
    struct ipc_namespace *ipc_ns = READ_KERN(ns->ipc_ns);
    return READ_KERN(ipc_ns->ns.inum);
}

static __always_inline u32 get_net_ns_id(struct nsproxy *ns)
{
    struct net *net_ns = READ_KERN(ns->net_ns);
    return READ_KERN(net_ns->ns.inum);
}

static __always_inline u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    struct cgroup_namespace *cgroup_ns = READ_KERN(ns->cgroup_ns);
    return READ_KERN(cgroup_ns->ns.inum);
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
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18
    nr = READ_KERN(READ_KERN(task->pids[PIDTYPE_PID].pid)->numbers[level].nr);
    #else
    // kernel 4.19 onwards
    struct pid *tpid = READ_KERN(task->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        struct pid_link *pl = READ_KERN(t->pids);
        struct pid *p = READ_KERN(pl[PIDTYPE_MAX].pid);
        nr = READ_KERN(p->numbers[level].nr);
    } else {
        struct pid *tpid = READ_KERN(task->thread_pid);
        nr = READ_KERN(tpid->numbers[level].nr);
    }
#endif

    return nr;
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18
    nr = READ_KERN(READ_KERN(group_leader->pids[PIDTYPE_PID].pid)->numbers[level].nr);
    #else
    // kernel 4.19 onwards
    struct pid *tpid = READ_KERN(group_leader->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *gl = (void *) group_leader;
        struct pid_link *pl = READ_KERN(gl->pids);
        struct pid *p = READ_KERN(pl[PIDTYPE_MAX].pid);
        nr = READ_KERN(p->numbers[level].nr);
    } else {
        struct pid *tpid = READ_KERN(group_leader->thread_pid);
        nr = READ_KERN(tpid->numbers[level].nr);
    }
#endif

    return nr;
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    int nr = 0;
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    struct nsproxy *namespaceproxy = READ_KERN(real_parent->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0)) &&        \
        !defined(CORE)
    // kernel 4.14-4.18
    nr = (READ_KERN(real_parent->pids[PIDTYPE_PID].pid)->numbers[level].nr);
    #else
    // kernel 4.19 onwards
    struct pid *tpid = READ_KERN(real_parent->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *rp = (void *) real_parent;
        struct pid_link *pl = READ_KERN(rp->pids);
        struct pid *p = READ_KERN(pl[PIDTYPE_MAX].pid);
        nr = READ_KERN(p->numbers[level].nr);
    } else {
        struct pid *tpid = READ_KERN(real_parent->thread_pid);
        nr = READ_KERN(tpid->numbers[level].nr);
    }
#endif

    return nr;
}

// HELPERS: TASKS ----------------------------------------------------------------------------------

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->tgid);
}

static __always_inline u64 get_task_start_time(struct task_struct *task)
{
    return READ_KERN(task->start_time);
}

static __always_inline u32 get_task_host_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

static __always_inline u32 get_task_host_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    return READ_KERN(task->real_parent);
}

static __always_inline u32 get_task_exit_code(struct task_struct *task)
{
    return READ_KERN(task->exit_code);
}

static __always_inline int get_task_parent_flags(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->flags);
}

static __always_inline const struct cred *get_task_real_cred(struct task_struct *task)
{
    return READ_KERN(task->real_cred);
}

// HELPERS: BINRPM ---------------------------------------------------------------------------------

static __always_inline const char *get_binprm_filename(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->filename);
}

static __always_inline const char *get_binprm_interp(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->interp);
}

static __always_inline struct file *get_file_ptr_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->file);
}

static __always_inline int get_argc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->argc);
}

static __always_inline int get_envc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->envc);
}

// HELPERS: CGROUPS --------------------------------------------------------------------------------

static __always_inline const char *get_cgroup_dirname(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return NULL;

    return READ_KERN(kn->name);
}

static __always_inline const u64 get_cgroup_id(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return 0;

    u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both situations

#ifdef CORE
    if (bpf_core_type_exists(union kernfs_node_id)) {
        struct kernfs_node___older_v55 *kn_old = (void *) kn;
        struct kernfs_node___rh8 *kn_rh8 = (void *) kn;

        if (bpf_core_field_exists(kn_rh8->id)) {
            // RHEL8 has both types declared: union and u64:
            //     kn->id
            //     rh->rh_kabi_hidden_172->id
            // pointing to the same data
            bpf_core_read(&id, sizeof(u64), &kn_rh8->id);
        } else {
            // all other regular kernels bellow v5.5
            bpf_core_read(&id, sizeof(u64), &kn_old->id);
        }

    } else {
        // kernel v5.5 and above
        bpf_core_read(&id, sizeof(u64), &kn->id);
    }
#else
    bpf_probe_read(&id, sizeof(u64), &kn->id);
#endif

    return id;
}

static __always_inline const u32 get_cgroup_hierarchy_id(struct cgroup *cgrp)
{
    struct cgroup_root *root = READ_KERN(cgrp->root);
    return READ_KERN(root->hierarchy_id);
}

static __always_inline const u64 get_cgroup_v1_subsys0_id(struct task_struct *task)
{
    struct css_set *cgroups = READ_KERN(task->cgroups);
    struct cgroup_subsys_state *subsys0 = READ_KERN(cgroups->subsys[0]);
    struct cgroup *cgroup = READ_KERN(subsys0->cgroup);
    return get_cgroup_id(cgroup);
}

static __always_inline bool is_x86_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return READ_KERN(task->thread_info.status) & TS_COMPAT;
#else
    return false;
#endif
}

// ARCHITECTURE ------------------------------------------------------------------------------------

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

// HELPERS: VFS ------------------------------------------------------------------------------------

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
    struct timespec64 ts = READ_KERN(f_inode->i_ctime);
    time64_t sec = READ_KERN(ts.tv_sec);
    if (sec < 0)
        return 0;
    long ns = READ_KERN(ts.tv_nsec);
    return (sec * 1000000000L) + ns;
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

// HELPERS: MEMORY ---------------------------------------------------------------------------------

static __always_inline struct mm_struct *get_mm_from_task(struct task_struct *task)
{
    return READ_KERN(task->mm);
}

static __always_inline unsigned long get_arg_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->arg_start);
}

static __always_inline unsigned long get_arg_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->arg_end);
}

static __always_inline unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_start);
}

static __always_inline unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_end);
}

static __always_inline unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return READ_KERN(vma->vm_flags);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

// HELPERS: NETWORK --------------------------------------------------------------------------------

static __always_inline u32 get_inet_rcv_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_rcv_saddr);
}

static __always_inline u32 get_inet_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_saddr);
}

static __always_inline u32 get_inet_daddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_daddr);
}

static __always_inline u16 get_inet_sport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_sport);
}

static __always_inline u16 get_inet_num(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_num);
}

static __always_inline u16 get_inet_dport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_dport);
}

static __always_inline struct sock *get_socket_sock(struct socket *socket)
{
    return READ_KERN(socket->sk);
}

static __always_inline u16 get_sock_family(struct sock *sock)
{
    return READ_KERN(sock->sk_family);
}

static __always_inline u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    // kernel 4.18-5.5: sk_protocol bit-field: use sk_gso_max_segs field and go
    // back 24 bits to reach sk_protocol field index.
    bpf_probe_read(&protocol, 1, (void *) (&sock->sk_gso_max_segs) - 3);
    #else
    // kernel 5.6
    protocol = READ_KERN(sock->sk_protocol);
    #endif
#else // CORE
    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset)) {
        check = (struct sock___old *) sock;
        bpf_core_read(&protocol, 1, (void *) (&check->sk_gso_max_segs) - 3);
    } else {
        protocol = READ_KERN(sock->sk_protocol);
    }
#endif

    return protocol;
}

static __always_inline u16 get_sockaddr_family(struct sockaddr *address)
{
    return READ_KERN(address->sa_family);
}

static __always_inline struct in6_addr get_sock_v6_rcv_saddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_rcv_saddr);
}

static __always_inline struct in6_addr get_ipv6_pinfo_saddr(struct ipv6_pinfo *np)
{
    return READ_KERN(np->saddr);
}

static __always_inline u32 get_ipv6_pinfo_flow_label(struct ipv6_pinfo *np)
{
    return READ_KERN(np->flow_label);
}

static __always_inline struct in6_addr get_sock_v6_daddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_daddr);
}

static __always_inline int get_sock_bound_dev_if(struct sock *sock)
{
    return READ_KERN(sock->sk_bound_dev_if);
}

static __always_inline volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_probe_read(
        (void *) &sk_state_own_impl, sizeof(sk_state_own_impl), (const void *) &sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo *get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct sockaddr_un get_unix_sock_addr(struct unix_sock *sock)
{
    struct unix_address *addr = READ_KERN(sock->addr);
    int len = READ_KERN(addr->len);
    struct sockaddr_un sockaddr = {};
    if (len <= sizeof(struct sockaddr_un)) {
        bpf_probe_read(&sockaddr, len, addr->name);
    }
    return sockaddr;
}

// INTERNAL: CONFIG --------------------------------------------------------------------------------

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

static __always_inline int get_kconfig_val(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&kconfig_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline void *get_symbol_addr(char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *) &new_ksym_name);

    if (sym == NULL)
        return 0;

    return *sym;
}

static __always_inline int get_iface_config(int ifindex)
{
    int *config = bpf_map_lookup_elem(&network_config, &ifindex);
    if (config == NULL)
        return 0;

    return *config;
}

// INTERNAL: CONTEXT -------------------------------------------------------------------------------

static __always_inline int
init_context(event_context_t *context, struct task_struct *task, u32 options)
{
    u64 id = bpf_get_current_pid_tgid();
    context->task.start_time = get_task_start_time(task);
    context->task.host_tid = id;
    context->task.host_pid = id >> 32;
    context->task.host_ppid = get_task_ppid(task);
    context->task.tid = get_task_ns_pid(task);
    context->task.pid = get_task_ns_tgid(task);
    context->task.ppid = get_task_ns_ppid(task);
    context->task.mnt_id = get_task_mnt_ns_id(task);
    context->task.pid_id = get_task_pid_ns_id(task);
    context->task.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->task.comm, sizeof(context->task.comm));
    char *uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(&context->task.uts_name, TASK_COMM_LEN, uts_name);
    if (options & OPT_CGROUP_V1) {
        context->task.cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        context->task.cgroup_id = bpf_get_current_cgroup_id();
    }

    context->ts = bpf_ktime_get_ns();
    context->argnum = 0;

    // Clean Stack Trace ID
    context->stack_id = 0;

    context->processor_id = (u16) bpf_get_smp_processor_id();

    return 0;
}

static __always_inline int init_event_data(event_data_t *data, void *ctx)
{
    int zero = 0;
    data->config = bpf_map_lookup_elem(&config_map, &zero);
    if (data->config == NULL)
        return 0;

    data->task = (struct task_struct *) bpf_get_current_task();
    init_context(&data->context, data->task, data->config->options);
    data->ctx = ctx;
    data->buf_off = sizeof(event_context_t);
    int buf_idx = SUBMIT_BUF_IDX;
    data->submit_p = bpf_map_lookup_elem(&bufs, &buf_idx);
    if (data->submit_p == NULL)
        return 0;

    // try updating task_info_map with noexist flag. If successful, we will need to initialize it
    // later. to save stack space (of size task_info_t) update the map with garbage data using the
    // submit buffer.
    int exist = bpf_map_update_elem(
        &task_info_map, &data->context.task.host_tid, data->submit_p, BPF_NOEXIST);
    data->task_info = bpf_map_lookup_elem(&task_info_map, &data->context.task.host_tid);
    if (data->task_info == NULL) {
        return 0;
    }
    if (!exist) {
        data->task_info->syscall_traced = false;
        data->task_info->new_task = false;
        data->task_info->follow = false;
        data->task_info->recompute_scope = true;
    } else {
        // check if we need to recompute scope due to context change
        task_context_t *old_context = &data->task_info->context;
        task_context_t *new_context = &data->context.task;

        if ((old_context->cgroup_id != new_context->cgroup_id) ||
            old_context->uid != new_context->uid || old_context->mnt_id != new_context->mnt_id ||
            old_context->pid_id != new_context->pid_id ||
            *(u64 *) old_context->comm != *(u64 *) new_context->comm ||
            *(u64 *) &old_context->comm[8] != *(u64 *) &new_context->comm[8] ||
            *(u64 *) old_context->uts_name != *(u64 *) new_context->uts_name ||
            *(u64 *) &old_context->uts_name[8] != *(u64 *) &new_context->uts_name[8])
            data->task_info->recompute_scope = true;
    }

    // update task_info with the new context
    bpf_probe_read(&data->task_info->context, sizeof(task_context_t), &data->context.task);

    return 1;
}

// INTERNAL: FILTERING -----------------------------------------------------------------------------

static __always_inline int
uint_filter_matches(bool filter_out, void *filter_map, u64 key, u32 less_idx, u32 greater_idx)
{
    u8 *equality = bpf_map_lookup_elem(filter_map, &key);
    if (equality != NULL)
        return *equality;

    if (!filter_out)
        return 0;

    u64 *lessThan = bpf_map_lookup_elem(&inequality_filter, &less_idx);
    if (lessThan == NULL)
        return 1;

    if ((*lessThan != LESS_NOT_SET) && (key >= *lessThan))
        return 0;

    u64 *greaterThan = bpf_map_lookup_elem(&inequality_filter, &greater_idx);
    if (greaterThan == NULL)
        return 1;

    if ((*greaterThan != GREATER_NOT_SET) && (key <= *greaterThan))
        return 0; // 0 means do not trace

    return 1; // 1 means trace
}

static __always_inline int equality_filter_matches(bool filter_out, void *filter_map, void *key)
{
    u32 *equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL)
        return *equality;

    if (!filter_out)
        return 0;

    return 1;
}

static __always_inline int bool_filter_matches(bool filter_out, bool val)
{
    if (!filter_out && val)
        return 1;

    if (filter_out && !val)
        return 1;

    return 0;
}

static __always_inline int do_should_trace(event_data_t *data)
{
    task_context_t *context = &data->context.task;
    u32 config = data->config->filters;

    if ((config & FILTER_FOLLOW_ENABLED) && (data->task_info->follow)) {
        // don't check the other filters if follow is set
        return 1;
    }

    // Don't monitor self
    if (data->config->tracee_pid == context->host_pid) {
        return 0;
    }

    if (config & FILTER_CONT_ENABLED) {
        bool is_container = false;
        u32 cgroup_id_lsb = context->cgroup_id;
        u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);
        if ((state != NULL) && (*state != CONTAINER_CREATED))
            is_container = true;
        bool filter_out = (config & FILTER_CONT_OUT) == FILTER_CONT_OUT;
        if (!bool_filter_matches(filter_out, is_container))
            return 0;
    }

    if (config & FILTER_NEW_CONT_ENABLED) {
        bool is_new_container = false;
        u32 cgroup_id_lsb = context->cgroup_id;
        u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);
        if ((state != NULL) && (*state == CONTAINER_STARTED))
            is_new_container = true;
        bool filter_out = (config & FILTER_NEW_CONT_OUT) == FILTER_NEW_CONT_OUT;
        if (!bool_filter_matches(filter_out, is_new_container))
            return 0;
    }

    if (config & FILTER_PID_ENABLED) {
        bool filter_out = (config & FILTER_PID_OUT) == FILTER_PID_OUT;
        if (!uint_filter_matches(filter_out, &pid_filter, context->host_tid, PID_LESS, PID_GREATER))
            return 0;
    }

    if (config & FILTER_NEW_PID_ENABLED) {
        bool filter_out = (config & FILTER_NEW_PID_OUT) == FILTER_NEW_PID_OUT;
        if (!bool_filter_matches(filter_out, data->task_info->new_task))
            return 0;
    }

    if (config & FILTER_UID_ENABLED) {
        bool filter_out = (config & FILTER_UID_OUT) == FILTER_UID_OUT;
        if (!uint_filter_matches(filter_out, &uid_filter, context->uid, UID_LESS, UID_GREATER))
            return 0;
    }

    if (config & FILTER_MNT_NS_ENABLED) {
        bool filter_out = (config & FILTER_MNT_NS_OUT) == FILTER_MNT_NS_OUT;
        if (!uint_filter_matches(
                filter_out, &mnt_ns_filter, context->mnt_id, MNTNS_LESS, MNTNS_GREATER))
            return 0;
    }

    if (config & FILTER_PID_NS_ENABLED) {
        bool filter_out = (config & FILTER_PID_NS_OUT) == FILTER_PID_NS_OUT;
        if (!uint_filter_matches(
                filter_out, &pid_ns_filter, context->pid_id, PIDNS_LESS, PIDNS_GREATER))
            return 0;
    }

    if (config & FILTER_UTS_NS_ENABLED) {
        bool filter_out = (config & FILTER_UTS_NS_OUT) == FILTER_UTS_NS_OUT;
        if (!equality_filter_matches(filter_out, &uts_ns_filter, &context->uts_name))
            return 0;
    }

    if (config & FILTER_COMM_ENABLED) {
        bool filter_out = (config & FILTER_COMM_OUT) == FILTER_COMM_OUT;
        if (!equality_filter_matches(filter_out, &comm_filter, &context->comm))
            return 0;
    }

    if (config & FILTER_PROC_TREE_ENABLED) {
        bool filter_out = (config & FILTER_PROC_TREE_OUT) == FILTER_PROC_TREE_OUT;
        if (!equality_filter_matches(filter_out, &process_tree_map, &context->pid))
            return 0;
    }

    if (config & FILTER_CGROUP_ID_ENABLED) {
        bool filter_out = (config & FILTER_CGROUP_ID_OUT) == FILTER_CGROUP_ID_OUT;
        u32 cgroup_id_lsb = context->cgroup_id;
        if (!equality_filter_matches(filter_out, &cgroup_id_filter, &cgroup_id_lsb))
            return 0;
    }

    // We passed all filters successfully
    return 1;
}

static __always_inline int should_trace(event_data_t *data)
{
    // use cache whenever possible
    if (data->task_info->recompute_scope) {
        data->task_info->should_trace = do_should_trace(data);
        data->task_info->recompute_scope = false;
    }

    return data->task_info->should_trace;
}

static __always_inline int should_submit(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&events_to_submit, &key);
    if (config == NULL)
        return 0;

    return *config;
}

// INTERNAL: BUFFERS -------------------------------------------------------------------------------

static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32 *get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

static __always_inline int save_to_submit_buf(event_data_t *data, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    // If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - (size + 1))
        return 0;

    // Save argument index
    volatile int buf_off = data->buf_off;
    data->submit_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off + 1) <= MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Read into buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1]), size, ptr) == 0) {
            // We update buf_off only if all writes were successful
            data->buf_off += size + 1;
            data->context.argnum++;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_bytes_to_buf(event_data_t *data, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][size][ ... bytes ... ]

    if (size == 0)
        return 0;

    // If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - (size + 1 + sizeof(int)))
        return 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;

    if ((data->buf_off + 1) <= MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE - sizeof(int)) {
        // Save size to buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1]), sizeof(int), &size) != 0) {
            return 0;
        }
    }

    if ((data->buf_off + 1 + sizeof(int)) <= MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE) {
        // Read bytes into buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1 + sizeof(int)]),
                           size & (MAX_BYTES_ARR_SIZE - 1),
                           ptr) == 0) {
            // We update buf_off only if all writes were successful
            data->buf_off += size + 1 + sizeof(int);
            data->context.argnum++;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_str_to_buf(event_data_t *data, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]
    // Note: If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off + 1) <= MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Read into buffer
        int sz = bpf_probe_read_str(
            &(data->submit_p->buf[data->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
            // Satisfy validator for probe read
            if ((data->buf_off + 1) > MAX_PERCPU_BUFSIZE - sizeof(int)) {
                return 0;
            }
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off + 1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
        }
    }

    return 0;
}

static __always_inline int
save_u64_arr_to_buf(event_data_t *data, const u64 __user *ptr, int len, u8 index)
{
    // Data saved to submit buf: [index][u64 count][u64 1][u64 2][u64 3]...
    u8 elem_num = 0;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off + 1;
    data->buf_off += 2;

#pragma unroll
    for (int i = 0; i < len; i++) {
        u64 element = 0;
        int err = bpf_probe_read(&element, sizeof(u64), &ptr[i]);
        if (err != 0)
            goto out;
        if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(u64))
            // not enough space - return
            goto out;

        void *addr = &(data->submit_p->buf[data->buf_off]);
        int sz = bpf_probe_read(addr, sizeof(u64), (void *) &element);
        if (sz == 0) {
            elem_num++;
            if (data->buf_off > MAX_PERCPU_BUFSIZE)
                // Satisfy validator
                goto out;

            data->buf_off += sizeof(u64);
            continue;
        } else {
            goto out;
        }
    }

    goto out;

out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE - 1)] = elem_num;
    data->context.argnum++;

    return 1;
}

static __always_inline int
save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off + 1;
    data->buf_off += 2;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(
            &(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(
        &(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
        data->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE - 1)] = elem_num;
    data->context.argnum++;
    return 1;
}

#define MAX_ARR_LEN 8192

static __always_inline int save_args_str_arr_to_buf(
    event_data_t *data, const char *start, const char *end, int elem_num, u8 index)
{
    // Data saved to submit buf: [index][len][arg #][null delimited string array]
    // Note: This helper saves null (0x00) delimited string array into buf

    if (start >= end)
        return 0;

    int len = end - start;
    if (len > (MAX_ARR_LEN - 1))
        len = MAX_ARR_LEN - 1;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off + 1) > MAX_PERCPU_BUFSIZE - sizeof(int))
        return 0;

    // Save array length
    bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1]), sizeof(int), &len);

    // Satisfy validator for probe read
    if ((data->buf_off + 5) > MAX_PERCPU_BUFSIZE - sizeof(int))
        return 0;

    // Save number of arguments
    bpf_probe_read(&(data->submit_p->buf[data->buf_off + 5]), sizeof(int), &elem_num);

    // Satisfy validator for probe read
    if ((data->buf_off + 9) > MAX_PERCPU_BUFSIZE - MAX_ARR_LEN)
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 9]), len & (MAX_ARR_LEN - 1), start) ==
        0) {
        // We update buf_off only if all writes were successful
        data->buf_off += len + 9;
        data->context.argnum++;
        return 1;
    }

    return 0;
}

// INTERNAL: PERF BUFFER ---------------------------------------------------------------------------

static __always_inline int events_perf_submit(event_data_t *data, u32 id, long ret)
{
    data->context.eventid = id;
    data->context.retval = ret;

    // Get Stack trace
    if (data->config->options & OPT_CAPTURE_STACK_TRACES) {
        int stack_id = bpf_get_stackid(data->ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            data->context.stack_id = stack_id;
        }
    }

    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(event_context_t), &data->context);

    // satisfy validator by setting buffer bounds
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE - 1);
    void *output_data = data->submit_p->buf;
    return bpf_perf_event_output(data->ctx, &events, BPF_F_CURRENT_CPU, output_data, size);
}

// INTERNAL: STRINGS -------------------------------------------------------------------------------

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

// HELPERS: VFS ------------------------------------------------------------------------------------

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

    set_buf_off(STRING_BUF_IDX, buf_off);
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

    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

// INTERNAL: ARGUMENTS -----------------------------------------------------------------------------

static __always_inline int save_args(args_t *args, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&args_map, &id, args, BPF_ANY);

    return 0;
}

static __always_inline int load_args(args_t *args, u32 event_id)
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

#define DEC_ARG(n, enc_arg) ((enc_arg >> (8 * n)) & 0xFF)

static __always_inline int save_args_to_submit_buf(event_data_t *data, u64 types, args_t *args)
{
    unsigned int i;
    unsigned int rc = 0;
    unsigned int arg_num = 0;
    short family = 0;

    if (types == 0)
        return 0;

#pragma unroll
    for (i = 0; i < 6; i++) {
        int size = 0;
        u8 type = DEC_ARG(i, types);
        u8 index = i;
        switch (type) {
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
                size = sizeof(void *);
                break;
            case STR_T:
                rc = save_str_to_buf(data, (void *) args->args[i], index);
                break;
            case SOCKADDR_T:
                if (args->args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void *) args->args[i]);
                    switch (family) {
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
                    rc = save_to_submit_buf(data, (void *) (args->args[i]), size, index);
                } else {
                    rc = save_to_submit_buf(data, &family, sizeof(short), index);
                }
                break;
            case INT_ARR_2_T:
                size = sizeof(int[2]);
                rc = save_to_submit_buf(data, (void *) (args->args[i]), size, index);
                break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T) && (type != INT_ARR_2_T)) {
            rc = save_to_submit_buf(data, (void *) &(args->args[i]), size, index);
        }

        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

// GENERIC PROBE MACROS ----------------------------------------------------------------------------

#define TRACE_ENT_FUNC(name, id)                                                                   \
    int trace_##name(struct pt_regs *ctx)                                                          \
    {                                                                                              \
        event_data_t data = {};                                                                    \
        if (!init_event_data(&data, ctx))                                                          \
            return 0;                                                                              \
                                                                                                   \
        if (!should_trace(&data))                                                                  \
            return 0;                                                                              \
                                                                                                   \
        args_t args = {};                                                                          \
        args.args[0] = PT_REGS_PARM1(ctx);                                                         \
        args.args[1] = PT_REGS_PARM2(ctx);                                                         \
        args.args[2] = PT_REGS_PARM3(ctx);                                                         \
        args.args[3] = PT_REGS_PARM4(ctx);                                                         \
        args.args[4] = PT_REGS_PARM5(ctx);                                                         \
        args.args[5] = PT_REGS_PARM6(ctx);                                                         \
                                                                                                   \
        return save_args(&args, id);                                                               \
    }

#define TRACE_RET_FUNC(name, id, types, ret)                                                       \
    int trace_ret_##name(void *ctx)                                                                \
    {                                                                                              \
        args_t args = {};                                                                          \
        if (load_args(&args, id) != 0)                                                             \
            return -1;                                                                             \
        del_args(id);                                                                              \
                                                                                                   \
        event_data_t data = {};                                                                    \
        if (!init_event_data(&data, ctx))                                                          \
            return 0;                                                                              \
                                                                                                   \
        if (!should_submit(id))                                                                    \
            return 0;                                                                              \
                                                                                                   \
        save_args_to_submit_buf(&data, types, &args);                                              \
                                                                                                   \
        return events_perf_submit(&data, id, ret);                                                 \
    }

// HELPERS: NETWORK --------------------------------------------------------------------------------

static __always_inline int
get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!peer) {
        net_details->local_address = get_inet_rcv_saddr(inet);
        net_details->local_port = bpf_ntohs(get_inet_num(inet));
        net_details->remote_address = get_inet_daddr(inet);
        net_details->remote_port = get_inet_dport(inet);
    } else {
        net_details->remote_address = get_inet_rcv_saddr(inet);
        net_details->remote_port = bpf_ntohs(get_inet_num(inet));
        net_details->local_address = get_inet_daddr(inet);
        net_details->local_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk,
                                                            struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

static __always_inline int
get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details, int peer)
{
    // inspired by 'inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)'
    // reference: https://elixir.bootlin.com/linux/latest/source/net/ipv6/af_inet6.c#L509

    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);

    struct in6_addr addr = {};
    addr = get_sock_v6_rcv_saddr(sk);
    if (ipv6_addr_any(&addr)) {
        addr = get_ipv6_pinfo_saddr(np);
    }

    // the flowinfo field can be specified by the user to indicate a network flow. how it is used by
    // the kernel, or whether it is enforced to be unique is not so obvious.  getting this value is
    // only supported by the kernel for outgoing packets using the 'struct ipv6_pinfo'.  in any
    // case, leaving it with value of 0 won't affect our representation of network flows.
    net_details->flowinfo = 0;

    // the scope_id field can be specified by the user to indicate the network interface from which
    // to send a packet. this only applies for link-local addresses, and is used only by the local
    // kernel.  getting this value is done by using the 'ipv6_iface_scope_id(const struct in6_addr
    // *addr, int iface)' function.  in any case, leaving it with value of 0 won't affect our
    // representation of network flows.
    net_details->scope_id = 0;

    if (peer) {
        net_details->local_address = get_sock_v6_daddr(sk);
        net_details->local_port = get_inet_dport(inet);
        net_details->remote_address = addr;
        net_details->remote_port = get_inet_sport(inet);
    } else {
        net_details->local_address = addr;
        net_details->local_port = get_inet_sport(inet);
        net_details->remote_address = get_sock_v6_daddr(sk);
        net_details->remote_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline int get_local_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                                      net_conn_v4_t *net_details,
                                                                      u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->local_port;
    addr->sin_addr.s_addr = net_details->local_address;

    return 0;
}

static __always_inline int get_remote_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                                       net_conn_v4_t *net_details,
                                                                       u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;

    return 0;
}

static __always_inline int get_local_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                                       net_conn_v6_t *net_details,
                                                                       u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->local_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->local_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                                        net_conn_v6_t *net_details,
                                                                        u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v4(struct sock *sk,
                                                                    net_id_t *connect_id,
                                                                    net_conn_v4_t *net_details,
                                                                    u16 family)
{
    connect_id->address.s6_addr32[3] = net_details->local_address;
    connect_id->address.s6_addr16[5] = 0xffff;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v6(struct sock *sk,
                                                                    net_id_t *connect_id,
                                                                    net_conn_v6_t *net_details,
                                                                    u16 family)
{
    connect_id->address = net_details->local_address;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

static __always_inline void invoke_fetch_network_seq_operations_event(event_data_t *data,
                                                                      unsigned long struct_address)
{
    struct seq_operations *seq_ops = (struct seq_operations *) struct_address;

    u64 show_addr = (u64) READ_KERN(seq_ops->show);
    if (show_addr == 0) {
        return;
    }

    u64 start_addr = (u64) READ_KERN(seq_ops->start);
    if (start_addr == 0) {
        return;
    }

    u64 next_addr = (u64) READ_KERN(seq_ops->next);
    if (next_addr == 0) {
        return;
    }

    u64 stop_addr = (u64) READ_KERN(seq_ops->stop);
    if (stop_addr == 0) {
        return;
    }
    u64 seq_ops_addresses[NET_SEQ_OPS_SIZE + 1] = {
        (u64) seq_ops, show_addr, start_addr, next_addr, stop_addr};
    save_u64_arr_to_buf(data, (const u64 *) seq_ops_addresses, 5, 0);
    events_perf_submit(data, PRINT_NET_SEQ_OPS, 0);
}

static __always_inline struct pipe_inode_info *get_file_pipe_info(struct file *file)
{
    struct pipe_inode_info *pipe = READ_KERN(file->private_data);
    char pipe_fops_sym[14] = "pipefifo_fops";
    if (READ_KERN(file->f_op) != get_symbol_addr(pipe_fops_sym)) {
        return NULL;
    }
    return pipe;
}

// SYSCALL HOOKS -----------------------------------------------------------------------------------

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    syscall_data_t *sys = &data.task_info->syscall_data;
    sys->id = ctx->args[1];

    if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)) {
        struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

        if (is_x86_compat(data.task)) {
#if defined(bpf_target_x86)
            sys->args.args[0] = READ_KERN(regs->bx);
            sys->args.args[1] = READ_KERN(regs->cx);
            sys->args.args[2] = READ_KERN(regs->dx);
            sys->args.args[3] = READ_KERN(regs->si);
            sys->args.args[4] = READ_KERN(regs->di);
            sys->args.args[5] = READ_KERN(regs->bp);
#endif // bpf_target_x86
        } else {
            sys->args.args[0] = READ_KERN(PT_REGS_PARM1(regs));
            sys->args.args[1] = READ_KERN(PT_REGS_PARM2(regs));
            sys->args.args[2] = READ_KERN(PT_REGS_PARM3(regs));
#if defined(bpf_target_x86)
            // x86-64: r10 used instead of rcx (4th param to a syscall)
            sys->args.args[3] = READ_KERN(regs->r10);
#else
            sys->args.args[3] = READ_KERN(PT_REGS_PARM4(regs));
#endif
            sys->args.args[4] = READ_KERN(PT_REGS_PARM5(regs));
            sys->args.args[5] = READ_KERN(PT_REGS_PARM6(regs));
        }
    } else {
        bpf_probe_read(sys->args.args, sizeof(6 * sizeof(u64)), (void *) ctx->args);
    }

    if (is_compat(data.task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys->id);
        if (id_64 == 0)
            return 0;

        sys->id = *id_64;
    }

    if (should_submit(RAW_SYS_ENTER)) {
        save_to_submit_buf(&data, (void *) &sys->id, sizeof(int), 0);
        events_perf_submit(&data, RAW_SYS_ENTER, 0);
    }

    // exit, exit_group and rt_sigreturn syscalls don't return
    if (sys->id != SYS_EXIT && sys->id != SYS_EXIT_GROUP && sys->id != SYS_RT_SIGRETURN) {
        sys->ts = data.context.ts;
        data.task_info->syscall_traced = true;
    }

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long ret)
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // check if syscall is being traced and mark that it finished
    if (!data.task_info->syscall_traced)
        return 0;
    data.task_info->syscall_traced = false;

    syscall_data_t *sys = &data.task_info->syscall_data;

    long ret = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
#if defined(bpf_target_x86)
    int id = READ_KERN(regs->orig_ax);
#elif defined(bpf_target_arm64)
    int id = READ_KERN(regs->syscallno);
#endif

    if (is_compat(data.task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // Sanity check - we returned from the expected syscall this task was executing
    if (sys->id != id)
        return 0;

    if (should_submit(RAW_SYS_EXIT)) {
        save_to_submit_buf(&data, (void *) &id, sizeof(int), 0);
        events_perf_submit(&data, RAW_SYS_EXIT, ret);
    }

    if (should_submit(id)) {
        u64 types = 0;
        u64 *saved_types = bpf_map_lookup_elem(&params_types_map, &id);
        if (!saved_types) {
            goto out;
        }
        types = *saved_types;
        if ((id != SYS_EXECVE && id != SYS_EXECVEAT) ||
            ((id == SYS_EXECVE || id == SYS_EXECVEAT) && (ret != 0))) {
            // We can't use saved args after execve syscall, as pointers are
            // invalid To avoid showing execve event both on entry and exit, we
            // only output failed execs
            data.buf_off = sizeof(event_context_t);
            data.context.argnum = 0;
            save_args_to_submit_buf(&data, types, &sys->args);
            data.context.ts = sys->ts;
            events_perf_submit(&data, id, ret);
        }
    }

out:
    sys->ret = ret;
    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_exit_tails, id);
    return 0;
}

// PROBES AND HELPERS ------------------------------------------------------------------------------

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!data.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &data.task_info->syscall_data;

    if (!should_submit(SYS_EXECVE))
        return 0;

    save_str_to_buf(&data, (void *) sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(&data, (const char *const *) sys->args.args[1] /*argv*/, 1);
    if (data.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(&data, (const char *const *) sys->args.args[2] /*envp*/, 2);
    }

    return events_perf_submit(&data, SYS_EXECVE, 0);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!data.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &data.task_info->syscall_data;

    if (!should_submit(SYS_EXECVEAT))
        return 0;

    save_to_submit_buf(&data, (void *) &sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(&data, (void *) sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(&data, (const char *const *) sys->args.args[2] /*argv*/, 2);
    if (data.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(&data, (const char *const *) sys->args.args[3] /*envp*/, 3);
    }
    save_to_submit_buf(&data, (void *) &sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_perf_submit(&data, SYS_EXECVEAT, 0);
}

static __always_inline int send_socket_dup(event_data_t *data, u64 oldfd, u64 newfd)
{
    if (!should_submit(SOCKET_DUP))
        return 0;

    if (!check_fd_type(oldfd, S_IFSOCK)) {
        return 0;
    }

    struct file *f = get_struct_file_from_fd(oldfd);
    if (f == NULL) {
        return -1;
    }

    // this is a socket - submit the SOCKET_DUP event

    save_to_submit_buf(data, &oldfd, sizeof(u32), 0);
    save_to_submit_buf(data, &newfd, sizeof(u32), 1);

    // get the address
    struct socket *socket_from_file = (struct socket *) READ_KERN(f->private_data);
    if (socket_from_file == NULL) {
        return -1;
    }

    struct sock *sk = get_socket_sock(socket_from_file);
    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in remote;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in), 2);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 remote;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in6), 2);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);

        save_to_submit_buf(data, &sockaddr, sizeof(struct sockaddr_un), 2);
    }

    return events_perf_submit(data, SOCKET_DUP, 0);
}

SEC("raw_tracepoint/sys_dup")
int sys_dup_exit_tail(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx)) {
        return 0;
    }

    if (!data.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &data.task_info->syscall_data;

    if (sys->ret < 0) {
        // dup failed
        return 0;
    }

    if (sys->id == SYS_DUP) {
        // args.args[0]: oldfd
        // retval: newfd
        send_socket_dup(&data, sys->args.args[0], sys->ret);
    } else if (sys->id == SYS_DUP2 || sys->id == SYS_DUP3) {
        // args.args[0]: oldfd
        // args.args[1]: newfd
        // retval: retval
        send_socket_dup(&data, sys->args.args[0], sys->args.args[1]);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *parent, struct task_struct *child)
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // Note: we don't place should_trace() here, so we can keep track of the cgroups in the system
    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    u64 start_time = get_task_start_time(child);

    task_info_t task = {};
    __builtin_memcpy(&task, data.task_info, sizeof(task_info_t));
    task.recompute_scope = true;
    task.context.tid = get_task_ns_pid(child);
    task.context.host_tid = get_task_host_pid(child);
    task.context.start_time = start_time;
    bpf_map_update_elem(&task_info_map, &task.context.host_tid, &task, BPF_ANY);

    int parent_pid = get_task_host_pid(parent);
    int child_pid = get_task_host_pid(child);

    int parent_tgid = get_task_host_tgid(parent);
    int child_tgid = get_task_host_tgid(child);

    // update process tree map if the parent has an entry
    if (data.config->filters & FILTER_PROC_TREE_ENABLED) {
        u32 *tgid_filtered = bpf_map_lookup_elem(&process_tree_map, &parent_tgid);
        if (tgid_filtered) {
            bpf_map_update_elem(&process_tree_map, &child_tgid, tgid_filtered, BPF_ANY);
        }
    }

    if (!should_trace(&data))
        return 0;

    // fork events may add new pids to the traced pids set.
    // perform this check after should_trace() to only add forked childs of a traced parent
    task.follow = true;
    task.new_task = true;
    bpf_map_update_elem(&task_info_map, &child_pid, &task, BPF_ANY);

    if (should_submit(SCHED_PROCESS_FORK) || data.config->options & OPT_PROCESS_INFO) {
        int parent_ns_pid = get_task_ns_pid(parent);
        int parent_ns_tgid = get_task_ns_tgid(parent);
        int child_ns_pid = get_task_ns_pid(child);
        int child_ns_tgid = get_task_ns_tgid(child);

        save_to_submit_buf(&data, (void *) &parent_pid, sizeof(int), 0);
        save_to_submit_buf(&data, (void *) &parent_ns_pid, sizeof(int), 1);
        save_to_submit_buf(&data, (void *) &parent_tgid, sizeof(int), 2);
        save_to_submit_buf(&data, (void *) &parent_ns_tgid, sizeof(int), 3);
        save_to_submit_buf(&data, (void *) &child_pid, sizeof(int), 4);
        save_to_submit_buf(&data, (void *) &child_ns_pid, sizeof(int), 5);
        save_to_submit_buf(&data, (void *) &child_tgid, sizeof(int), 6);
        save_to_submit_buf(&data, (void *) &child_ns_tgid, sizeof(int), 7);
        save_to_submit_buf(&data, (void *) &start_time, sizeof(u64), 8);

        events_perf_submit(&data, SCHED_PROCESS_FORK, 0);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // Perform the following checks before should_trace() so we can filter by newly created
    // containers/processes.  We assume that a new container/pod has started when a process of a
    // newly created cgroup and mount ns executed a binary
    u32 cgroup_id_lsb = data.context.task.cgroup_id;
    u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);
    if (state != NULL && *state == CONTAINER_CREATED) {
        u32 mntns = get_task_mnt_ns_id(data.task);
        struct task_struct *parent = get_parent_task(data.task);
        u32 parent_mntns = get_task_mnt_ns_id(parent);
        if (mntns != parent_mntns)
            *state = CONTAINER_STARTED;
    }

    data.task_info->new_task = true;
    data.task_info->recompute_scope = true;

    if (!should_trace(&data))
        return 0;

    // We passed all filters (in should_trace()) - add this pid to traced pids set
    data.task_info->follow = true;

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];

    if (bprm == NULL) {
        return -1;
    }

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD) {
        invoked_from_kernel = 1;
    }

    const char *interp = get_binprm_interp(bprm);

    const char *filename = get_binprm_filename(bprm);

    struct file *file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);

    // bprm->mm is null at this point (set by begin_new_exec()), and task->mm is already initialized
    struct mm_struct *mm = get_mm_from_task(task);

    unsigned long arg_start, arg_end;
    arg_start = get_arg_start_from_mm(mm);
    arg_end = get_arg_end_from_mm(mm);
    int argc = get_argc_from_bprm(bprm);

    unsigned long env_start, env_end;
    env_start = get_env_start_from_mm(mm);
    env_end = get_env_end_from_mm(mm);
    int envc = get_envc_from_bprm(bprm);

    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    // The map of the interpreter will be updated for any loading of an elf, both for the elf and
    // for the interpreter. Because the interpreter is loaded only after the executed elf is loaded,
    // the map value of the executed elf should be overridden by the interpreter.
    file_id_t *elf_interpreter = bpf_map_lookup_elem(&interpreter_map, &data.context.task.host_tid);

    unsigned short stdin_type = get_inode_mode_from_fd(0) & S_IFMT;

    // Note: Starting from kernel 5.9, there are two new interesting fields in bprm that we should
    // consider adding:
    // 1. struct file *executable - can be used to get the executable name passed to an interpreter
    // 2. fdpath                  - generated filename for execveat (after resolving dirfd)

    if (should_submit(SCHED_PROCESS_EXEC) || data.config->options & OPT_PROCESS_INFO) {
        save_str_to_buf(&data, (void *) filename, 0);
        save_str_to_buf(&data, file_path, 1);
        save_args_str_arr_to_buf(&data, (void *) arg_start, (void *) arg_end, argc, 2);
        if (data.config->options & OPT_EXEC_ENV) {
            save_args_str_arr_to_buf(&data, (void *) env_start, (void *) env_end, envc, 3);
        }
        save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 4);
        save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 5);
        save_to_submit_buf(&data, &invoked_from_kernel, sizeof(int), 6);
        save_to_submit_buf(&data, &ctime, sizeof(u64), 7);
        save_to_submit_buf(&data, &stdin_type, sizeof(unsigned short), 8);
        save_str_to_buf(&data, (void *) interp, 9);
        if (elf_interpreter != NULL) {
            save_str_to_buf(&data, &elf_interpreter->pathname, 10);
            save_to_submit_buf(&data, &elf_interpreter->device, sizeof(dev_t), 11);
            save_to_submit_buf(&data, &elf_interpreter->inode, sizeof(unsigned long), 12);
        }

        events_perf_submit(&data, SCHED_PROCESS_EXEC, 0);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // evaluate should_trace before removing this pid from the maps
    bool traced = should_trace(&data);

    // Remove this pid from all maps
    bpf_map_delete_elem(&task_info_map, &data.context.task.host_tid);
    bpf_map_delete_elem(&interpreter_map, &data.context.task.host_tid);

    int proc_tree_filter_set = data.config->filters & FILTER_PROC_TREE_ENABLED;

    bool group_dead = false;
    struct task_struct *task = data.task;
    struct signal_struct *signal = READ_KERN(task->signal);
    atomic_t live = READ_KERN(signal->live);
    // This check could be true for multiple thread exits if the thread count was 0 when the hooks
    // were triggered. This could happen for example if the threads performed exit in different CPUs
    // simultaneously.
    if (live.counter == 0) {
        group_dead = true;
        if (proc_tree_filter_set) {
            bpf_map_delete_elem(&process_tree_map, &data.context.task.host_pid);
        }
    }

    if (!traced)
        return 0;

    long exit_code = get_task_exit_code(data.task);

    if (should_submit(SCHED_PROCESS_EXIT) || data.config->options & OPT_PROCESS_INFO) {
        save_to_submit_buf(&data, (void *) &exit_code, sizeof(long), 0);
        save_to_submit_buf(&data, (void *) &group_dead, sizeof(bool), 1);

        events_perf_submit(&data, SCHED_PROCESS_EXIT, 0);
    }

    return 0;
}

SEC("raw_tracepoint/syscall__accept4")
int syscall__accept4(void *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, SOCKET_ACCEPT) != 0) {
        // missed entry or not traced
        return 0;
    }

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct socket *old_sock = (struct socket *) saved_args.args[0];
    struct socket *new_sock = (struct socket *) saved_args.args[1];

    del_args(SOCKET_ACCEPT);

    if (new_sock == NULL) {
        return -1;
    }
    if (old_sock == NULL) {
        return -1;
    }

    struct sock *sk_new = get_socket_sock(new_sock);
    struct sock *sk_old = get_socket_sock(old_sock);

    u16 family_old = get_sock_family(sk_old);
    u16 family_new = get_sock_family(sk_new);

    if (family_old == AF_INET && family_new == AF_INET) {
        net_conn_v4_t net_details_old = {};
        struct sockaddr_in local;
        get_network_details_from_sock_v4(sk_old, &net_details_old, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details_old, family_old);

        save_to_submit_buf(&data, (void *) &local, sizeof(struct sockaddr_in), 1);

        net_conn_v4_t net_details_new = {};
        struct sockaddr_in remote;
        get_network_details_from_sock_v4(sk_new, &net_details_new, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details_new, family_new);

        save_to_submit_buf(&data, (void *) &remote, sizeof(struct sockaddr_in), 2);
    } else if (family_old == AF_INET6 && family_new == AF_INET6) {
        net_conn_v6_t net_details_old = {};
        struct sockaddr_in6 local;
        get_network_details_from_sock_v6(sk_old, &net_details_old, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details_old, family_old);

        save_to_submit_buf(&data, (void *) &local, sizeof(struct sockaddr_in6), 1);

        net_conn_v6_t net_details_new = {};

        struct sockaddr_in6 remote;
        get_network_details_from_sock_v6(sk_new, &net_details_new, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details_new, family_new);

        save_to_submit_buf(&data, (void *) &remote, sizeof(struct sockaddr_in6), 2);
    } else if (family_old == AF_UNIX && family_new == AF_UNIX) {
        struct unix_sock *unix_sk_new = (struct unix_sock *) sk_new;
        struct sockaddr_un sockaddr_new = get_unix_sock_addr(unix_sk_new);
        save_to_submit_buf(&data, (void *) &sockaddr_new, sizeof(struct sockaddr_un), 1);
    } else {
        return 0;
    }
    return events_perf_submit(&data, SOCKET_ACCEPT, 0);
}

// trace/events/sched.h: TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    if (!should_submit(SCHED_SWITCH))
        return 0;

    struct task_struct *prev = (struct task_struct *) ctx->args[1];
    struct task_struct *next = (struct task_struct *) ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(&data, (void *) &cpu, sizeof(int), 0);
    save_to_submit_buf(&data, (void *) &prev_pid, sizeof(int), 1);
    save_str_to_buf(&data, prev->comm, 2);
    save_to_submit_buf(&data, (void *) &next_pid, sizeof(int), 3);
    save_str_to_buf(&data, next->comm, 4);

    return events_perf_submit(&data, SCHED_SWITCH, 0);
}

SEC("kprobe/filldir64")
int BPF_KPROBE(trace_filldir64)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (!should_trace((&data)))
        return 0;

    char *process_name = (char *) PT_REGS_PARM2(ctx);
    unsigned long process_inode_number = (unsigned long) PT_REGS_PARM5(ctx);
    if (process_inode_number == 0) {
        save_str_to_buf(&data, process_name, 0);
        return events_perf_submit(&data, HIDDEN_INODES, 0);
    }
    return 0;
}

SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(trace_call_usermodehelper)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    void *path = (void *) PT_REGS_PARM1(ctx);
    unsigned long argv = PT_REGS_PARM2(ctx);
    unsigned long envp = PT_REGS_PARM3(ctx);
    int wait = PT_REGS_PARM4(ctx);

    save_str_to_buf(&data, path, 0);
    save_str_arr_to_buf(&data, (const char *const *) argv, 1);
    save_str_arr_to_buf(&data, (const char *const *) envp, 2);
    save_to_submit_buf(&data, (void *) &wait, sizeof(int), 3);

    return events_perf_submit(&data, CALL_USERMODE_HELPER, 0);
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    long code = PT_REGS_PARM1(ctx);

    return events_perf_submit(&data, DO_EXIT, code);
}

/* invoke_print_syscall_table_event submit to the buff the syscalls function handlers address from
 * the syscall table. the syscalls are strode in map which is syscalls_to_check_map and the
 * syscall-table address is stored in the kernel_symbols map.
 */
static __always_inline void invoke_print_syscall_table_event(event_data_t *data)
{
    int key = 0;
    u64 *table_ptr = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &key);
    if (table_ptr == NULL) {
        return;
    }

    char syscall_table[15] = "sys_call_table";
    unsigned long *syscall_table_addr = (unsigned long *) get_symbol_addr(syscall_table);
    u64 idx;
    u64 *syscall_num_p; // pointer to syscall_number
    u64 syscall_num;
    unsigned long syscall_addr = 0;
    int monitored_syscalls_amount = 0;
#if defined(bpf_target_x86)
    monitored_syscalls_amount = NUMBER_OF_SYSCALLS_TO_CHECK_X86;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK_X86];
#elif defined(bpf_target_arm64)
    monitored_syscalls_amount = NUMBER_OF_SYSCALLS_TO_CHECK_ARM;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK_ARM];
#else

    return
#endif

    __builtin_memset(syscall_address, 0, sizeof(syscall_address));
// the map should look like [syscall number 1][syscall number 2][syscall number 3]...
#pragma unroll
    for (int i = 0; i < monitored_syscalls_amount; i++) {
        idx = i;
        syscall_num_p = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &idx);
        if (syscall_num_p == NULL) {
            continue;
        }
        syscall_num = (u64) *syscall_num_p;
        syscall_addr = READ_KERN(syscall_table_addr[syscall_num]);
        if (syscall_addr == 0) {
            return;
        }
        syscall_address[i] = syscall_addr;
    }
    save_u64_arr_to_buf(data, (const u64 *) syscall_address, monitored_syscalls_amount, 0);
    events_perf_submit(data, PRINT_SYSCALL_TABLE, 0);
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(trace_tracee_trigger_event)
{
    event_data_t data = {};

    if (!init_event_data(&data, ctx))
        return 0;

    unsigned int cmd = PT_REGS_PARM2(ctx);
    if ((cmd & IOCTL_FETCH_SYSCALLS) == IOCTL_FETCH_SYSCALLS &&
        data.config->tracee_pid == data.context.task.host_pid) {
        invoke_print_syscall_table_event(&data);
    }

    if ((cmd & IOCTL_HOOKED_SEQ_OPS) == IOCTL_HOOKED_SEQ_OPS &&
        data.config->tracee_pid == data.context.task.host_pid) {
        unsigned long struct_address = PT_REGS_PARM3(ctx);
        invoke_fetch_network_seq_operations_event(&data, struct_address);
    }

    return 0;
}

// trace/events/cgroup.h:
// TP_PROTO(struct cgroup *dst_cgrp, const char *path, struct task_struct *task, bool threadgroup)
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    char *path = (char *) ctx->args[1];
    struct task_struct *task = (struct task_struct *) ctx->args[2];

    int pid = get_task_host_pid(task);
    char *comm = READ_KERN(task->comm);

    save_str_to_buf(&data, path, 0);
    save_str_to_buf(&data, comm, 1);
    save_to_submit_buf(&data, (void *) &pid, sizeof(int), 2);
    events_perf_submit(&data, CGROUP_ATTACH_TASK, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((data.config->options & OPT_CGROUP_V1) && (data.config->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update) {
        // Assume this is a new container. If not, userspace code will delete this entry
        u8 state = CONTAINER_CREATED;
        bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
    }

    save_to_submit_buf(&data, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&data, path, 1);
    save_to_submit_buf(&data, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&data, CGROUP_MKDIR, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((data.config->options & OPT_CGROUP_V1) && (data.config->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update)
        bpf_map_delete_elem(&containers_map, &cgroup_id_lsb);

    save_to_submit_buf(&data, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&data, path, 1);
    save_to_submit_buf(&data, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&data, CGROUP_RMDIR, 0);

    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    struct file *file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    save_str_to_buf(&data, file_path, 0);
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 2);

    return events_perf_submit(&data, SECURITY_BPRM_CHECK, 0);
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    save_str_to_buf(&data, file_path, 0);
    save_to_submit_buf(&data, (void *) GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 4);
    if (data.config->options & OPT_SHOW_SYSCALL) {
        syscall_data_t *sys = &data.task_info->syscall_data;
        if (data.task_info->syscall_traced) {
            save_to_submit_buf(&data, (void *) &sys->id, sizeof(int), 5);
        }
    }

    return events_perf_submit(&data, SECURITY_FILE_OPEN, 0);
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_security_sb_mount)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    const char *dev_name = (const char *) PT_REGS_PARM1(ctx);
    struct path *path = (struct path *) PT_REGS_PARM2(ctx);
    const char *type = (const char *) PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long) PT_REGS_PARM4(ctx);

    void *path_str = get_path_str(path);

    save_str_to_buf(&data, (void *) dev_name, 0);
    save_str_to_buf(&data, path_str, 1);
    save_str_to_buf(&data, (void *) type, 2);
    save_to_submit_buf(&data, &flags, sizeof(unsigned long), 3);

    return events_perf_submit(&data, SECURITY_SB_MOUNT, 0);
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&data, dentry_path, 0);

    return events_perf_submit(&data, SECURITY_INODE_UNLINK, 0);
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct cred *new = (struct cred *) PT_REGS_PARM1(ctx);
    struct cred *old = (struct cred *) get_task_real_cred(data.task);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    struct user_namespace *userns_old = READ_KERN(old->user_ns);
    struct user_namespace *userns_new = READ_KERN(new->user_ns);

    old_slim.uid = READ_KERN(old->uid.val);
    old_slim.gid = READ_KERN(old->gid.val);
    old_slim.suid = READ_KERN(old->suid.val);
    old_slim.sgid = READ_KERN(old->sgid.val);
    old_slim.euid = READ_KERN(old->euid.val);
    old_slim.egid = READ_KERN(old->egid.val);
    old_slim.fsuid = READ_KERN(old->fsuid.val);
    old_slim.fsgid = READ_KERN(old->fsgid.val);
    old_slim.user_ns = READ_KERN(userns_old->ns.inum);
    old_slim.securebits = READ_KERN(old->securebits);

    new_slim.uid = READ_KERN(new->uid.val);
    new_slim.gid = READ_KERN(new->gid.val);
    new_slim.suid = READ_KERN(new->suid.val);
    new_slim.sgid = READ_KERN(new->sgid.val);
    new_slim.euid = READ_KERN(new->euid.val);
    new_slim.egid = READ_KERN(new->egid.val);
    new_slim.fsuid = READ_KERN(new->fsuid.val);
    new_slim.fsgid = READ_KERN(new->fsgid.val);
    new_slim.user_ns = READ_KERN(userns_new->ns.inum);
    new_slim.securebits = READ_KERN(new->securebits);

    // Currently, (2021), there are ~40 capabilities in the Linux kernel which are stored in an u32
    // array of length 2. This might change in the (not so near) future as more capabilities will be
    // added. For now, we use u64 to store this array in one piece

    kernel_cap_t caps;
    caps = READ_KERN(old->cap_inheritable);
    old_slim.cap_inheritable = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_permitted);
    old_slim.cap_permitted = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_effective);
    old_slim.cap_effective = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_bset);
    old_slim.cap_bset = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(old->cap_ambient);
    old_slim.cap_ambient = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];

    caps = READ_KERN(new->cap_inheritable);
    new_slim.cap_inheritable = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_permitted);
    new_slim.cap_permitted = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_effective);
    new_slim.cap_effective = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_bset);
    new_slim.cap_bset = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];
    caps = READ_KERN(new->cap_ambient);
    new_slim.cap_ambient = ((caps.cap[1] + 0ULL) << 32) + caps.cap[0];

    save_to_submit_buf(&data, (void *) &old_slim, sizeof(slim_cred_t), 0);
    save_to_submit_buf(&data, (void *) &new_slim, sizeof(slim_cred_t), 1);

    if ((old_slim.uid != new_slim.uid) || (old_slim.gid != new_slim.gid) ||
        (old_slim.suid != new_slim.suid) || (old_slim.sgid != new_slim.sgid) ||
        (old_slim.euid != new_slim.euid) || (old_slim.egid != new_slim.egid) ||
        (old_slim.fsuid != new_slim.fsuid) || (old_slim.fsgid != new_slim.fsgid) ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable) ||
        (old_slim.cap_permitted != new_slim.cap_permitted) ||
        (old_slim.cap_effective != new_slim.cap_effective) ||
        (old_slim.cap_bset != new_slim.cap_bset) ||
        (old_slim.cap_ambient != new_slim.cap_ambient)) {
        if (data.config->options & OPT_SHOW_SYSCALL) {
            syscall_data_t *sys = &data.task_info->syscall_data;
            if (data.task_info->syscall_traced) {
                save_to_submit_buf(&data, (void *) &sys->id, sizeof(int), 2);
            }
        }

        events_perf_submit(&data, COMMIT_CREDS, 0);
    }

    return 0;
}

SEC("kprobe/switch_task_namespaces")
int BPF_KPROBE(trace_switch_task_namespaces)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct task_struct *task = (struct task_struct *) PT_REGS_PARM1(ctx);
    struct nsproxy *new = (struct nsproxy *) PT_REGS_PARM2(ctx);

    if (!new)
        return 0;

    pid_t pid = READ_KERN(task->pid);
    u32 old_mnt = data.context.task.mnt_id;
    u32 new_mnt = get_mnt_ns_id(new);
    u32 old_pid = data.context.task.pid_id;
    u32 new_pid = get_pid_ns_id(new);
    u32 old_uts = get_task_uts_ns_id(task);
    u32 new_uts = get_uts_ns_id(new);
    u32 old_ipc = get_task_ipc_ns_id(task);
    u32 new_ipc = get_ipc_ns_id(new);
    u32 old_net = get_task_net_ns_id(task);
    u32 new_net = get_net_ns_id(new);
    u32 old_cgroup = get_task_cgroup_ns_id(task);
    u32 new_cgroup = get_cgroup_ns_id(new);

    save_to_submit_buf(&data, (void *) &pid, sizeof(int), 0);

    if (old_mnt != new_mnt)
        save_to_submit_buf(&data, (void *) &new_mnt, sizeof(u32), 1);
    if (old_pid != new_pid)
        save_to_submit_buf(&data, (void *) &new_pid, sizeof(u32), 2);
    if (old_uts != new_uts)
        save_to_submit_buf(&data, (void *) &new_uts, sizeof(u32), 3);
    if (old_ipc != new_ipc)
        save_to_submit_buf(&data, (void *) &new_ipc, sizeof(u32), 4);
    if (old_net != new_net)
        save_to_submit_buf(&data, (void *) &new_net, sizeof(u32), 5);
    if (old_cgroup != new_cgroup)
        save_to_submit_buf(&data, (void *) &new_cgroup, sizeof(u32), 6);
    if (data.context.argnum > 1)
        events_perf_submit(&data, SWITCH_TASK_NS, 0);

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(&data, (void *) &cap, sizeof(int), 0);
    if (data.config->options & OPT_SHOW_SYSCALL) {
        syscall_data_t *sys = &data.task_info->syscall_data;
        if (data.task_info->syscall_traced) {
            save_to_submit_buf(&data, (void *) &sys->id, sizeof(int), 1);
        }
    }

    return events_perf_submit(&data, CAP_CAPABLE, 0);
}

SEC("kprobe/security_socket_create")
int BPF_KPROBE(trace_security_socket_create)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    int family = (int) PT_REGS_PARM1(ctx);
    int type = (int) PT_REGS_PARM2(ctx);
    int protocol = (int) PT_REGS_PARM3(ctx);
    int kern = (int) PT_REGS_PARM4(ctx);

    save_to_submit_buf(&data, (void *) &family, sizeof(int), 0);
    save_to_submit_buf(&data, (void *) &type, sizeof(int), 1);
    save_to_submit_buf(&data, (void *) &protocol, sizeof(int), 2);
    save_to_submit_buf(&data, (void *) &kern, sizeof(int), 3);

    return events_perf_submit(&data, SECURITY_SOCKET_CREATE, 0);
}

SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(trace_security_inode_symlink)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    const char *old_name = (const char *) PT_REGS_PARM3(ctx);

    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&data, dentry_path, 0);
    save_str_to_buf(&data, (void *) old_name, 1);

    return events_perf_submit(&data, SECURITY_INODE_SYMLINK, 0);
}

SEC("kprobe/proc_create")
int BPF_KPROBE(trace_proc_create)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (!should_trace((&data)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM4(ctx);

    save_str_to_buf(&data, name, 0);
    save_to_submit_buf(&data, (void *) &proc_ops_addr, sizeof(u64), 1);

    return events_perf_submit(&data, PROC_CREATE, 0);
}

SEC("kprobe/debugfs_create_file")
int BPF_KPROBE(trace_debugfs_create_file)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (!should_trace((&data)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    mode_t mode = (unsigned short) PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM3(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM5(ctx);

    save_str_to_buf(&data, name, 0);
    save_str_to_buf(&data, dentry_path, 1);
    save_to_submit_buf(&data, &mode, sizeof(mode_t), 2);
    save_to_submit_buf(&data, (void *) &proc_ops_addr, sizeof(u64), 3);

    return events_perf_submit(&data, DEBUGFS_CREATE_FILE, 0);
}

SEC("kprobe/debugfs_create_dir")
int BPF_KPROBE(trace_debugfs_create_dir)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (!should_trace((&data)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&data, name, 0);
    save_str_to_buf(&data, dentry_path, 1);

    return events_perf_submit(&data, DEBUGFS_CREATE_DIR, 0);
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int backlog = (int) PT_REGS_PARM2(ctx);

    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the listen syscall (which eventually invokes this function)
    syscall_data_t *sys = &data.task_info->syscall_data;
    if (!data.task_info->syscall_traced || sys->id != SYSCALL_LISTEN)
        return 0;

    save_to_submit_buf(&data, (void *) &sys->args.args[0], sizeof(u32), 0);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *) &local, sizeof(struct sockaddr_in), 1);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *) &local, sizeof(struct sockaddr_in6), 1);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(&data, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
    }

    save_to_submit_buf(&data, (void *) &backlog, sizeof(int), 2);

    return events_perf_submit(&data, SECURITY_SOCKET_LISTEN, 0);
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    uint addr_len = (uint) PT_REGS_PARM3(ctx);

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the connect syscall (which eventually invokes this function)
    syscall_data_t *sys = &data.task_info->syscall_data;
    if (!data.task_info->syscall_traced || sys->id != SYSCALL_CONNECT)
        return 0;

    save_to_submit_buf(&data, (void *) &sys->args.args[0], sizeof(u32), 0);

    if (sa_fam == AF_INET) {
        save_to_submit_buf(&data, (void *) address, sizeof(struct sockaddr_in), 1);
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(&data, (void *) address, sizeof(struct sockaddr_in6), 1);
    } else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *) address);
            save_to_submit_buf(&data, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(&data, (void *) address, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&data, SECURITY_SOCKET_CONNECT, 0);
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    struct socket *new_sock = (struct socket *) PT_REGS_PARM2(ctx);

    // save sockets for "socket_accept event"
    if (should_submit(SOCKET_ACCEPT)) {
        args_t args = {};
        args.args[0] = (unsigned long) sock;
        args.args[1] = (unsigned long) new_sock;
        save_args(&args, SOCKET_ACCEPT);
    }
    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the accept syscall (which eventually invokes this function)
    syscall_data_t *sys = &data.task_info->syscall_data;
    if (!data.task_info->syscall_traced ||
        (sys->id != SYSCALL_ACCEPT && sys->id != SYSCALL_ACCEPT4))
        return 0;

    save_to_submit_buf(&data, (void *) &sys->args.args[0], sizeof(u32), 0);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *) &local, sizeof(struct sockaddr_in), 1);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *) &local, sizeof(struct sockaddr_in6), 1);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(&data, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&data, SECURITY_SOCKET_ACCEPT, 0);
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    uint addr_len = (uint) PT_REGS_PARM3(ctx);

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the bind syscall (which eventually invokes this function)
    syscall_data_t *sys = &data.task_info->syscall_data;
    if (!data.task_info->syscall_traced || sys->id != SYSCALL_BIND)
        return 0;

    save_to_submit_buf(&data, (void *) &sys->args.args[0], sizeof(u32), 0);

    u16 protocol = get_sock_protocol(sk);
    net_id_t connect_id = {0};
    connect_id.protocol = protocol;

    if (sa_fam == AF_INET) {
        save_to_submit_buf(&data, (void *) address, sizeof(struct sockaddr_in), 1);

        struct sockaddr_in *addr = (struct sockaddr_in *) address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin_port)) {
            connect_id.address.s6_addr32[3] = READ_KERN(addr->sin_addr).s_addr;
            connect_id.address.s6_addr16[5] = 0xffff;
            connect_id.port = READ_KERN(addr->sin_port);
        }
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(&data, (void *) address, sizeof(struct sockaddr_in6), 1);

        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin6_port)) {
            connect_id.address = READ_KERN(addr->sin6_addr);
            connect_id.port = READ_KERN(addr->sin6_port);
        }
    } else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *) address);
            save_to_submit_buf(&data, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(&data, (void *) address, sizeof(struct sockaddr_un), 1);
    }

    if (connect_id.port) {
        net_ctx_t net_ctx;
        net_ctx.host_tid = data.context.task.host_tid;
        __builtin_memcpy(net_ctx.comm, data.context.task.comm, TASK_COMM_LEN);
        bpf_map_update_elem(&network_map, &connect_id, &net_ctx, BPF_ANY);
    }

    // netDebug event
    if ((data.config->options & OPT_DEBUG_NET) && (sa_fam != AF_UNIX)) {
        net_debug_t debug_event = {0};
        debug_event.ts = data.context.ts;
        debug_event.host_tid = data.context.task.host_tid;
        __builtin_memcpy(debug_event.comm, data.context.task.comm, TASK_COMM_LEN);
        debug_event.event_id = DEBUG_NET_SECURITY_BIND;
        debug_event.local_addr = connect_id.address;
        debug_event.local_port = __bpf_ntohs(connect_id.port);
        debug_event.protocol = protocol;
        bpf_perf_event_output(
            ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return events_perf_submit(&data, SECURITY_SOCKET_BIND, 0);
}

// To delete socket from net map use tid==0, otherwise, update
static __always_inline int
net_map_update_or_delete_sock(void *ctx, int event_id, struct sock *sk, u32 tid)
{
    net_id_t connect_id = {0};
    u16 family = get_sock_family(sk);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);
        if (net_details.local_port)
            get_local_net_id_from_network_details_v4(sk, &connect_id, &net_details, family);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        get_network_details_from_sock_v6(sk, &net_details, 0);
        if (net_details.local_port)
            get_local_net_id_from_network_details_v6(sk, &connect_id, &net_details, family);
    }

    if (connect_id.port) {
        if (tid != 0) {
            net_ctx_t net_ctx;
            net_ctx.host_tid = tid;
            bpf_get_current_comm(&net_ctx.comm, sizeof(net_ctx.comm));
            bpf_map_update_elem(&network_map, &connect_id, &net_ctx, BPF_ANY);
        } else {
            bpf_map_delete_elem(&network_map, &connect_id);
        }
    }

    int zero = 0;
    config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
    if (config == NULL)
        return 0;

    // netDebug event
    if (config->options & OPT_DEBUG_NET) {
        net_debug_t debug_event = {0};
        debug_event.ts = bpf_ktime_get_ns();
        debug_event.host_tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&debug_event.comm, sizeof(debug_event.comm));
        debug_event.event_id = event_id;
        debug_event.local_addr = connect_id.address;
        debug_event.local_port = __bpf_ntohs(connect_id.port);
        debug_event.protocol = connect_id.protocol;
        bpf_perf_event_output(
            ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(
        ctx, DEBUG_NET_UDP_SENDMSG, sk, data.context.task.host_tid);
}

SEC("kprobe/__udp_disconnect")
int BPF_KPROBE(trace_udp_disconnect)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_DISCONNECT, sk, 0);
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(trace_udp_destroy_sock)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_DESTROY_SOCK, sk, 0);
}

SEC("kprobe/udpv6_destroy_sock")
int BPF_KPROBE(trace_udpv6_destroy_sock)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDPV6_DESTROY_SOCK, sk, 0);
}

// trace/events/sock.h: TP_PROTO(const struct sock *sk, const int oldstate, const int newstate)
SEC("raw_tracepoint/inet_sock_set_state")
int tracepoint__inet_sock_set_state(struct bpf_raw_tracepoint_args *ctx)
{
    net_id_t connect_id = {0};
    net_debug_t debug_event = {0};
    net_ctx_ext_t net_ctx_ext = {0};

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct sock *sk = (struct sock *) ctx->args[0];
    int old_state = ctx->args[1];
    int new_state = ctx->args[2];

    // Sometimes the socket state may be changed by other contexts that handle the tcp network stack
    // (e.g. network driver). In these cases, we won't pass the should_trace() check. To overcome
    // this problem, we save the socket pointer in sock_ctx_map in states that we observed to have
    // the correct context. We can then check for the existence of a socket in the map, and continue
    // if it was traced before.

    net_ctx_ext_t *sock_ctx_p = bpf_map_lookup_elem(&sock_ctx_map, &sk);
    if (!sock_ctx_p) {
        if (!should_trace(&data)) {
            return 0;
        }
    }

    u16 family = get_sock_family(sk);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_net_id_from_network_details_v4(sk, &connect_id, &net_details, family);

        debug_event.local_addr.s6_addr32[3] = net_details.local_address;
        debug_event.local_addr.s6_addr16[5] = 0xffff;
        debug_event.local_port = __bpf_ntohs(net_details.local_port);
        debug_event.remote_addr.s6_addr32[3] = net_details.remote_address;
        debug_event.remote_addr.s6_addr16[5] = 0xffff;
        debug_event.remote_port = __bpf_ntohs(net_details.remote_port);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_net_id_from_network_details_v6(sk, &connect_id, &net_details, family);

        debug_event.local_addr = net_details.local_address;
        debug_event.local_port = __bpf_ntohs(net_details.local_port);
        debug_event.remote_addr = net_details.remote_address;
        debug_event.remote_port = __bpf_ntohs(net_details.remote_port);
    } else {
        return 0;
    }

    switch (new_state) {
        case TCP_LISTEN:
            if (connect_id.port) {
                if (!sock_ctx_p) {
                    net_ctx_ext.host_tid = data.context.task.host_tid;
                    bpf_get_current_comm(&net_ctx_ext.comm, sizeof(net_ctx_ext.comm));
                    net_ctx_ext.local_port = connect_id.port;
                    bpf_map_update_elem(&sock_ctx_map, &sk, &net_ctx_ext, BPF_ANY);
                    bpf_map_update_elem(&network_map, &connect_id, &net_ctx_ext, BPF_ANY);
                } else {
                    sock_ctx_p->local_port = connect_id.port;
                    bpf_map_update_elem(&network_map, &connect_id, sock_ctx_p, BPF_ANY);
                }
            }
            break;
        case TCP_CLOSE:
            // At this point, port equals 0, so we will not be able to use current connect_id as a
            // key to network map.  We used the value saved in sock_ctx_map instead.
            if (sock_ctx_p) {
                connect_id.port = sock_ctx_p->local_port;
            }
            bpf_map_delete_elem(&sock_ctx_map, &sk);
            bpf_map_delete_elem(&network_map, &connect_id);
            break;
    }

    // netDebug event
    if (data.config->options & OPT_DEBUG_NET) {
        debug_event.ts = data.context.ts;
        if (!sock_ctx_p) {
            debug_event.host_tid = data.context.task.host_tid;
            bpf_get_current_comm(&debug_event.comm, sizeof(debug_event.comm));
        } else {
            debug_event.host_tid = sock_ctx_p->host_tid;
            __builtin_memcpy(debug_event.comm, sock_ctx_p->comm, TASK_COMM_LEN);
        }
        debug_event.event_id = DEBUG_NET_INET_SOCK_SET_STATE;
        debug_event.old_state = old_state;
        debug_event.new_state = new_state;
        debug_event.sk_ptr = (u64) sk;
        debug_event.protocol = connect_id.protocol;
        bpf_perf_event_output(
            ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    net_id_t connect_id = {0};
    net_ctx_ext_t net_ctx_ext = {0};

    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);

    u16 family = get_sock_family(sk);
    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_net_id_from_network_details_v4(sk, &connect_id, &net_details, family);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_net_id_from_network_details_v6(sk, &connect_id, &net_details, family);
    } else {
        return 0;
    }

    net_ctx_ext.host_tid = data.context.task.host_tid;
    bpf_get_current_comm(&net_ctx_ext.comm, sizeof(net_ctx_ext.comm));
    net_ctx_ext.local_port = connect_id.port;
    bpf_map_update_elem(&sock_ctx_map, &sk, &net_ctx_ext, BPF_ANY);

    return net_map_update_or_delete_sock(
        ctx, DEBUG_NET_TCP_CONNECT, sk, data.context.task.host_tid);
}

static __always_inline int icmp_delete_network_map(struct sk_buff *skb, int send, int ipv6)
{
    net_id_t connect_id = {0};
    __u8 icmp_type;

    if (ipv6) {
        connect_id.protocol = IPPROTO_ICMPV6;

        struct ipv6hdr *ip_header =
            (struct ipv6hdr *) (READ_KERN(skb->head) + READ_KERN(skb->network_header));
        struct in6_addr daddr = READ_KERN(ip_header->daddr);
        struct in6_addr saddr = READ_KERN(ip_header->saddr);

        struct icmp6hdr *icmph =
            (struct icmp6hdr *) (READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        icmp_type = READ_KERN(icmph->icmp6_type);

        connect_id.port = READ_KERN(icmph->icmp6_dataun.u_echo.identifier);

        if (send) {
            connect_id.address = daddr;
        } else {
            if (icmp_type == ICMPV6_ECHO_REQUEST) {
                return 0;
            }

            connect_id.address = saddr;
        }
    } else {
        connect_id.protocol = IPPROTO_ICMP;

        struct iphdr *ip_header =
            (struct iphdr *) (READ_KERN(skb->head) + READ_KERN(skb->network_header));
        __be32 daddr = READ_KERN(ip_header->daddr);
        __be32 saddr = READ_KERN(ip_header->saddr);

        struct icmphdr *icmph =
            (struct icmphdr *) (READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        icmp_type = READ_KERN(icmph->type);

        connect_id.port = READ_KERN(icmph->un.echo.id);

        if (send) {
            connect_id.address.s6_addr32[3] = daddr;
        } else {
            if (icmp_type == ICMP_ECHO) {
                return 0;
            }
#ifdef ICMP_EXT_ECHO
            if (icmp_type == ICMP_EXT_ECHO) {
                return 0;
            }
#endif

            connect_id.address.s6_addr32[3] = saddr;
        }
        connect_id.address.s6_addr16[5] = 0xffff;
    }

    bpf_map_delete_elem(&network_map, &connect_id);

    return 0;
}

SEC("kprobe/icmp_send")
int BPF_KPROBE(trace_icmp_send)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    icmp_delete_network_map(skb, 1, 0);

    return 0;
}

SEC("kprobe/icmp6_send")
int BPF_KPROBE(trace_icmp6_send)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    icmp_delete_network_map(skb, 1, 1);

    return 0;
}

SEC("kprobe/icmp_rcv")
int BPF_KPROBE(trace_icmp_rcv)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    icmp_delete_network_map(skb, 0, 0);

    return 0;
}

SEC("kprobe/icmpv6_rcv")
int BPF_KPROBE(trace_icmpv6_rcv)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    icmp_delete_network_map(skb, 0, 1);

    return 0;
}

SEC("kprobe/ping_v4_sendmsg")
int BPF_KPROBE(trace_ping_v4_sendmsg)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    net_id_t connect_id = {0};

    // this is v4 function
    connect_id.protocol = IPPROTO_ICMP;

    // get the icmp id
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    struct inet_sock *inet = inet_sk(sk);
    u16 sport = get_inet_sport(inet);
    connect_id.port = sport;

    // get the address
    struct msghdr *msg = (struct msghdr *) PT_REGS_PARM2(ctx);
    struct sockaddr_in *addr = (struct sockaddr_in *) READ_KERN(msg->msg_name);
    connect_id.address.s6_addr32[3] = READ_KERN(addr->sin_addr).s_addr;
    connect_id.address.s6_addr16[5] = 0xffff;

    // update the map
    net_ctx_t net_ctx;
    net_ctx.host_tid = data.context.task.host_tid;
    __builtin_memcpy(net_ctx.comm, data.context.task.comm, TASK_COMM_LEN);
    bpf_map_update_elem(&network_map, &connect_id, &net_ctx, BPF_ANY);

    return 0;
}

SEC("kprobe/ping_v6_sendmsg")
int BPF_KPROBE(trace_ping_v6_sendmsg)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    net_id_t connect_id = {0};

    // this is v6 function
    connect_id.protocol = IPPROTO_ICMPV6;

    // get the icmp id
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    struct inet_sock *inet = inet_sk(sk);
    u16 sport = get_inet_sport(inet);
    connect_id.port = sport;

    // get the address
    struct msghdr *msg = (struct msghdr *) PT_REGS_PARM2(ctx);
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *) READ_KERN(msg->msg_name);
    connect_id.address = READ_KERN(addr->sin6_addr);

    // update the map
    net_ctx_t net_ctx;
    net_ctx.host_tid = data.context.task.host_tid;
    __builtin_memcpy(net_ctx.comm, data.context.task.comm, TASK_COMM_LEN);
    bpf_map_update_elem(&network_map, &connect_id, &net_ctx, BPF_ANY);

    return 0;
}

static __always_inline u32 send_bin_helper(void *ctx, void *prog_array, int tail_call)
{
    // Note: sending the data to the userspace have the following constraints:
    //
    // 1. We need a buffer that we know it's exact size
    //    (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data
    //    can be overridden if userspace doesn't consume
    //    it fast enough

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
            // Handle the rest of write recursively
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
            bin_args->ptr = io_vec.iov_base;
            bin_args->full_size = io_vec.iov_len;
            bpf_tail_call(ctx, prog_array, tail_call);
        }
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    buf_t *file_buf_p = get_buf(FILE_BUF_IDX);
    if (file_buf_p == NULL) {
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

#define F_SEND_TYPE  0
#define F_CGROUP_ID  (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF   (F_CGROUP_ID + sizeof(u64))
#define F_SZ_OFF     (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF    (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF  (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE (MAX_PERCPU_BUFSIZE >> 1)

    bpf_probe_read((void **) &(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args->type);

    int zero = 0;
    config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
    if (config == NULL)
        return 0;

    u64 cgroup_id;
    if (config->options & OPT_CGROUP_V1) {
        cgroup_id = get_cgroup_v1_subsys0_id((struct task_struct *) bpf_get_current_task());
    } else {
        cgroup_id = bpf_get_current_cgroup_id();
    }
    bpf_probe_read((void **) &(file_buf_p->buf[F_CGROUP_ID]), sizeof(u64), &cgroup_id);

    // Save metadata to be used in filename
    bpf_probe_read((void **) &(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args->metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read((void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = bin_args->full_size / F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

// Handle full chunks in loop
#pragma unroll
    for (i = 0; i < MAX_BIN_CHUNKS; i++) {
        // Dummy instruction, as break instruction can't be first with unroll optimization
        chunk_size = F_CHUNK_SIZE;

        if (i == full_chunk_num)
            break;

        // Save binary chunk and file position of write
        bpf_probe_read(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);
        bpf_probe_read((void **) &(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, bin_args->ptr);
        bin_args->ptr += F_CHUNK_SIZE;
        bin_args->start_off += F_CHUNK_SIZE;

        bpf_perf_event_output(
            ctx, &file_writes, BPF_F_CURRENT_CPU, data, F_CHUNK_OFF + F_CHUNK_SIZE);
    }

    chunk_size = bin_args->full_size - i * F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        // Handle the rest of write recursively
        bin_args->full_size = chunk_size;
        bpf_tail_call(ctx, prog_array, tail_call);
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    if (chunk_size) {
        // Save last chunk
        chunk_size = chunk_size & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
        bpf_probe_read((void **) &(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
        bpf_probe_read((void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
        bpf_probe_read(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

        // Satisfy validator by setting buffer bounds
        int size = (F_CHUNK_OFF + chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
        bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, size);
    }

    // We finished writing an element of the vector - continue to next element
    bin_args->iov_idx++;
    if (bin_args->iov_idx < bin_args->iov_len) {
        // Handle the rest of write recursively
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
        bin_args->ptr = io_vec.iov_base;
        bin_args->full_size = io_vec.iov_len;
        bpf_tail_call(ctx, prog_array, tail_call);
    }

    bpf_map_delete_elem(&bin_args_map, &id);
    return 0;
}

SEC("kprobe/send_bin")
int BPF_KPROBE(send_bin)
{
    return send_bin_helper(ctx, &prog_array, TAIL_SEND_BIN);
}

SEC("raw_tracepoint/send_bin_tp")
int send_bin_tp(void *ctx)
{
    return send_bin_helper(ctx, &prog_array_tp, TAIL_SEND_BIN_TP);
}

static __always_inline int
do_file_write_operation(struct pt_regs *ctx, u32 event_id, u32 tail_call_id)
{
    args_t saved_args;
    if (load_args(&saved_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    if (!should_submit(VFS_WRITE) && !should_submit(VFS_WRITEV) && !should_submit(__KERNEL_WRITE) &&
        !should_submit(MAGIC_WRITE)) {
        bpf_tail_call(ctx, &prog_array, tail_call_id);
        return 0;
    }

    loff_t start_pos;
    void *ptr;
    struct iovec *vec;
    size_t count;
    unsigned long vlen;

    struct file *file = (struct file *) saved_args.args[0];
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE) {
        ptr = (void *) saved_args.args[1];
        count = (size_t) saved_args.args[2];
    } else {
        vec = (struct iovec *) saved_args.args[1];
        vlen = saved_args.args[2];
    }
    loff_t *pos = (loff_t *) saved_args.args[3];

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

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (should_submit(VFS_WRITE) || should_submit(VFS_WRITEV) || should_submit(__KERNEL_WRITE)) {
        save_str_to_buf(&data, file_path, 0);
        save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 1);
        save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 2);

        if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE)
            save_to_submit_buf(&data, &count, sizeof(size_t), 3);
        else
            save_to_submit_buf(&data, &vlen, sizeof(unsigned long), 3);
        save_to_submit_buf(&data, &start_pos, sizeof(off_t), 4);

        // Submit vfs_write(v) event
        events_perf_submit(&data, event_id, PT_REGS_RC(ctx));
    }

    // magic_write event checks if the header of some file is changed
    if (should_submit(MAGIC_WRITE) && !char_dev && (start_pos == 0)) {
        data.buf_off = sizeof(event_context_t);
        data.context.argnum = 0;

        u8 header[FILE_MAGIC_HDR_SIZE];

        save_str_to_buf(&data, file_path, 0);

        if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE) {
            if (header_bytes < FILE_MAGIC_HDR_SIZE)
                bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, ptr);
            else
                bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, ptr);
        } else {
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &vec[0]);
            if (header_bytes < FILE_MAGIC_HDR_SIZE)
                bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, io_vec.iov_base);
            else
                bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, io_vec.iov_base);
        }

        save_bytes_to_buf(&data, header, header_bytes, 1);
        save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 2);
        save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 3);

        // Submit magic_write event
        events_perf_submit(&data, MAGIC_WRITE, PT_REGS_RC(ctx));
    }

    bpf_tail_call(ctx, &prog_array, tail_call_id);
    return 0;
}

static __always_inline int do_file_write_operation_tail(struct pt_regs *ctx, u32 event_id)
{
    args_t saved_args;
    bin_args_t bin_args = {};
    loff_t start_pos;

    void *ptr;
    struct iovec *vec;
    unsigned long vlen;
    bool has_filter = false;
    bool filter_match = false;

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (load_args(&saved_args, event_id) != 0)
        return 0;
    del_args(event_id);

    struct file *file = (struct file *) saved_args.args[0];
    if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE) {
        ptr = (void *) saved_args.args[1];
    } else {
        vec = (struct iovec *) saved_args.args[1];
        vlen = saved_args.args[2];
    }
    loff_t *pos = (loff_t *) saved_args.args[3];

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    get_path_str(GET_FIELD_ADDR(file->f_path));
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

        if (has_prefix(filter_p->path, (char *) &string_p->buf[*off], MAX_PATH_PREF_SIZE)) {
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
    u32 pid = data.context.task.pid;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
        return -1;

    if (!has_prefix("/dev/null", (char *) &string_p->buf[*off], 10))
        pid = 0;

    if (data.config->options & OPT_CAPTURE_FILES) {
        bin_args.type = SEND_VFS_WRITE;
        bpf_probe_read(bin_args.metadata, 4, &s_dev);
        bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
        bpf_probe_read(&bin_args.metadata[12], 4, &i_mode);
        bpf_probe_read(&bin_args.metadata[16], 4, &pid);
        bin_args.start_off = start_pos;
        if (event_id == VFS_WRITE || event_id == __KERNEL_WRITE) {
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
    return do_file_write_operation(ctx, VFS_WRITE, TAIL_VFS_WRITE);
}

SEC("kretprobe/vfs_write_tail")
int BPF_KPROBE(trace_ret_vfs_write_tail)
{
    return do_file_write_operation_tail(ctx, VFS_WRITE);
}

SEC("kprobe/vfs_writev")
TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(trace_ret_vfs_writev)
{
    return do_file_write_operation(ctx, VFS_WRITEV, TAIL_VFS_WRITEV);
}

SEC("kretprobe/vfs_writev_tail")
int BPF_KPROBE(trace_ret_vfs_writev_tail)
{
    return do_file_write_operation_tail(ctx, VFS_WRITEV);
}

SEC("kprobe/__kernel_write")
TRACE_ENT_FUNC(kernel_write, __KERNEL_WRITE);

SEC("kretprobe/__kernel_write")
int BPF_KPROBE(trace_ret_kernel_write)
{
    return do_file_write_operation(ctx, __KERNEL_WRITE, TAIL_KERNEL_WRITE);
}

SEC("kretprobe/__kernel_write_tail")
int BPF_KPROBE(trace_ret_kernel_write_tail)
{
    return do_file_write_operation_tail(ctx, __KERNEL_WRITE);
}

SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_alert)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // Load the arguments given to the mmap syscall (which eventually invokes this function)
    syscall_data_t *sys = &data.task_info->syscall_data;
    if (!data.task_info->syscall_traced || sys->id != SYS_MMAP)
        return 0;

    if ((sys->args.args[2] & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)) {
        u32 alert = ALERT_MMAP_W_X;
        save_to_submit_buf(&data, &alert, sizeof(u32), 0);
        events_perf_submit(&data, MEM_PROT_ALERT, 0);
    }

    return 0;
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(trace_security_mmap_file)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == 0)
        return 0;
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);
    unsigned long prot = (unsigned long) PT_REGS_PARM2(ctx);
    unsigned long mmap_flags = (unsigned long) PT_REGS_PARM3(ctx);

    save_str_to_buf(&data, file_path, 0);
    save_to_submit_buf(&data, (void *) GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 4);

    syscall_data_t *sys = &data.task_info->syscall_data;
    if (should_submit(SHARED_OBJECT_LOADED)) {
        if (data.task_info->syscall_traced && (prot & VM_EXEC) == VM_EXEC && sys->id == SYS_MMAP) {
            events_perf_submit(&data, SHARED_OBJECT_LOADED, 0);
        }
    }

    if (should_submit(SECURITY_MMAP_FILE)) {
        save_to_submit_buf(&data, &prot, sizeof(int), 5);
        save_to_submit_buf(&data, &mmap_flags, sizeof(int), 6);
        if (data.config->options & OPT_SHOW_SYSCALL) {
            if (data.task_info->syscall_traced) {
                save_to_submit_buf(&data, (void *) &sys->id, sizeof(int), 7);
            }
        }
        return events_perf_submit(&data, SECURITY_MMAP_FILE, 0);
    }

    return 0;
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_security_file_mprotect)
{
    bin_args_t bin_args = {};

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct vm_area_struct *vma = (struct vm_area_struct *) PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);

    if (should_submit(SECURITY_FILE_MPROTECT)) {
        if (!should_trace(&data))
            return 0;

        struct file *file = (struct file *) READ_KERN(vma->vm_file);
        void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
        u64 ctime = get_ctime_nanosec_from_file(file);
        save_str_to_buf(&data, file_path, 0);
        save_to_submit_buf(&data, &reqprot, sizeof(int), 1);
        save_to_submit_buf(&data, &ctime, sizeof(u64), 2);
        events_perf_submit(&data, SECURITY_FILE_MPROTECT, 0);
    }

    if (should_submit(MEM_PROT_ALERT)) {
        // Load the arguments given to the mprotect syscall (which eventually invokes this function)
        syscall_data_t *sys = &data.task_info->syscall_data;
        if (!data.task_info->syscall_traced || sys->id != SYS_MPROTECT)
            return 0;

        // unsigned long prot = PT_REGS_PARM3(ctx);
        unsigned long prev_prot = get_vma_flags(vma);

        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];

        if (addr <= 0)
            return 0;

        // If length is 0, the current page permissions are changed
        if (len == 0)
            len = PAGE_SIZE;

        if ((!(prev_prot & VM_EXEC)) && (reqprot & VM_EXEC)) {
            u32 alert = ALERT_MPROT_X_ADD;
            save_to_submit_buf(&data, &alert, sizeof(u32), 0);
            return events_perf_submit(&data, MEM_PROT_ALERT, 0);
        }

        if ((prev_prot & VM_EXEC) && !(prev_prot & VM_WRITE) &&
            ((reqprot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC))) {
            u32 alert = ALERT_MPROT_W_ADD;
            save_to_submit_buf(&data, &alert, sizeof(u32), 0);
            return events_perf_submit(&data, MEM_PROT_ALERT, 0);
        }

        if (((prev_prot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)) && (reqprot & VM_EXEC) &&
            !(reqprot & VM_WRITE)) {
            u32 alert = ALERT_MPROT_W_REM;
            save_to_submit_buf(&data, &alert, sizeof(u32), 0);
            events_perf_submit(&data, MEM_PROT_ALERT, 0);

            if (data.config->options & OPT_EXTRACT_DYN_CODE) {
                bin_args.type = SEND_MPROTECT;
                bpf_probe_read(bin_args.metadata, sizeof(u64), &data.context.ts);
                bin_args.ptr = (char *) addr;
                bin_args.start_off = 0;
                bin_args.full_size = len;

                u64 id = bpf_get_current_pid_tgid();
                bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
                bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
            }
        }
    }

    return 0;
}

SEC("raw_tracepoint/sys_init_module")
int syscall__init_module(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    syscall_data_t *sys = &data.task_info->syscall_data;
    if (!data.task_info->syscall_traced)
        return -1;

    bin_args_t bin_args = {};

    u32 pid = data.context.task.host_pid;
    u64 dummy = 0;
    void *addr = (void *) sys->args.args[0];
    unsigned long len = (unsigned long) sys->args.args[1];

    if (data.config->options & OPT_CAPTURE_MODULES) {
        bin_args.type = SEND_KERNEL_MODULE;
        bpf_probe_read(bin_args.metadata, 4, &dummy);
        bpf_probe_read(&bin_args.metadata[4], 8, &dummy);
        bpf_probe_read(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read(&bin_args.metadata[16], 8, &len);
        bin_args.ptr = (char *) addr;
        bin_args.start_off = 0;
        bin_args.full_size = (unsigned int) len;

        u64 id = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);
        bpf_tail_call(ctx, &prog_array_tp, TAIL_SEND_BIN_TP);
    }
    return 0;
}

SEC("kprobe/security_bpf")
int BPF_KPROBE(trace_security_bpf)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    int cmd = (int) PT_REGS_PARM1(ctx);

    // 1st argument == cmd (int)
    save_to_submit_buf(&data, (void *) &cmd, sizeof(int), 0);

    return events_perf_submit(&data, SECURITY_BPF, 0);
}

SEC("kprobe/arm_kprobe")
int BPF_KPROBE(trace_arm_kprobe)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct kprobe *kp = (struct kprobe *) PT_REGS_PARM1(ctx);

    char *symbol_name = (char *) READ_KERN(kp->symbol_name);
    u64 pre_handler = (u64) READ_KERN(kp->pre_handler);
    u64 post_handler = (u64) READ_KERN(kp->post_handler);

    save_str_to_buf(&data, (void *) symbol_name, 0);
    save_to_submit_buf(&data, (void *) &pre_handler, sizeof(u64), 1);
    save_to_submit_buf(&data, (void *) &post_handler, sizeof(u64), 2);

    return events_perf_submit(&data, KPROBE_ATTACH, 0);
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(trace_security_bpf_map)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct bpf_map *map = (struct bpf_map *) PT_REGS_PARM1(ctx);

    // 1st argument == map_id (u32)
    save_to_submit_buf(&data, (void *) GET_FIELD_ADDR(map->id), sizeof(int), 0);
    // 2nd argument == map_name (const char *)
    save_str_to_buf(&data, (void *) GET_FIELD_ADDR(map->name), 1);

    return events_perf_submit(&data, SECURITY_BPF_MAP, 0);
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM2(ctx);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    save_str_to_buf(&data, file_path, 0);
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 2);
    save_to_submit_buf(&data, &type_id, sizeof(int), 3);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 4);

    return events_perf_submit(&data, SECURITY_KERNEL_READ_FILE, 0);
}

SEC("kprobe/security_kernel_post_read_file")
int BPF_KPROBE(trace_security_kernel_post_read_file)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    bin_args_t bin_args = {};
    u64 id = bpf_get_current_pid_tgid();

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    u32 pid = data.context.task.host_pid;

    char *buf = (char *) PT_REGS_PARM2(ctx);
    loff_t size = (loff_t) PT_REGS_PARM3(ctx);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM4(ctx);

    // Send event if chosen
    if (should_submit(SECURITY_POST_READ_FILE)) {
        void *file_path = get_path_str(&file->f_path);
        save_str_to_buf(&data, file_path, 0);
        save_to_submit_buf(&data, &size, sizeof(loff_t), 1);
        save_to_submit_buf(&data, &type_id, sizeof(int), 2);
        events_perf_submit(&data, SECURITY_POST_READ_FILE, 0);
    }

    if (data.config->options & OPT_CAPTURE_MODULES) {
        // Extract device id, inode number for file name
        dev_t s_dev = get_dev_from_file(file);
        unsigned long inode_nr = get_inode_nr_from_file(file);

        bin_args.type = SEND_KERNEL_MODULE;
        bpf_probe_read(bin_args.metadata, 4, &s_dev);
        bpf_probe_read(&bin_args.metadata[4], 8, &inode_nr);
        bpf_probe_read(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read(&bin_args.metadata[16], 8, &size);
        bin_args.start_off = 0;
        bin_args.ptr = buf;
        bin_args.full_size = size;
        bpf_map_update_elem(&bin_args_map, &id, &bin_args, BPF_ANY);

        // Send file data
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
    }

    return 0;
}

SEC("kprobe/security_inode_mknod")
int BPF_KPROBE(trace_security_inode_mknod)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    unsigned short mode = (unsigned short) PT_REGS_PARM3(ctx);
    unsigned int dev = (unsigned int) PT_REGS_PARM4(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&data, dentry_path, 0);
    save_to_submit_buf(&data, &mode, sizeof(unsigned short), 1);
    save_to_submit_buf(&data, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&data, SECURITY_INODE_MKNOD, 0);
}

SEC("kprobe/device_add")
int BPF_KPROBE(trace_device_add)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct device *dev = (struct device *) PT_REGS_PARM1(ctx);
    const char *name = get_device_name(dev);

    struct device *parent_dev = READ_KERN(dev->parent);
    const char *parent_name = get_device_name(parent_dev);

    save_str_to_buf(&data, (void *) name, 0);
    save_str_to_buf(&data, (void *) parent_name, 1);

    return events_perf_submit(&data, DEVICE_ADD, 0);
}

SEC("kprobe/__register_chrdev")
TRACE_ENT_FUNC(__register_chrdev, REGISTER_CHRDEV);

SEC("kretprobe/__register_chrdev")
int BPF_KPROBE(trace_ret__register_chrdev)
{
    args_t saved_args;
    if (load_args(&saved_args, REGISTER_CHRDEV) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(REGISTER_CHRDEV);

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    unsigned int major_number = (unsigned int) saved_args.args[0];
    unsigned int returned_major = PT_REGS_RC(ctx);

    // sets the returned major to the requested one in case of a successful registration
    if (major_number > 0 && returned_major == 0) {
        returned_major = major_number;
    }

    char *char_device_name = (char *) saved_args.args[3];
    struct file_operations *char_device_fops = (struct file_operations *) saved_args.args[4];

    save_to_submit_buf(&data, &major_number, sizeof(unsigned int), 0);
    save_to_submit_buf(&data, &returned_major, sizeof(unsigned int), 1);
    save_str_to_buf(&data, char_device_name, 2);
    save_to_submit_buf(&data, &char_device_fops, sizeof(void *), 3);

    return events_perf_submit(&data, REGISTER_CHRDEV, 0);
}

static __always_inline struct pipe_buffer *get_last_write_pipe_buffer(struct pipe_inode_info *pipe)
{
    // Extract the last page buffer used in the pipe for write
    struct pipe_buffer *bufs = READ_KERN(pipe->bufs);
    unsigned int curbuf;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0))
    unsigned int nrbufs = READ_KERN(pipe->nrbufs);
    if (nrbufs > 0) {
        nrbufs--;
    }
    curbuf = (READ_KERN(pipe->curbuf) + nrbufs) & (READ_KERN(pipe->buffers) - 1);
    #else
    int head = READ_KERN(pipe->head);
    int ring_size = READ_KERN(pipe->ring_size);
    curbuf = (head - 1) & (ring_size - 1);
    #endif
#else // CORE
    struct pipe_inode_info___v54 *legacy_pipe = (struct pipe_inode_info___v54 *) pipe;
    if (bpf_core_field_exists(legacy_pipe->nrbufs)) {
        unsigned int nrbufs = READ_KERN(legacy_pipe->nrbufs);
        if (nrbufs > 0) {
            nrbufs--;
        }
        curbuf = (READ_KERN(legacy_pipe->curbuf) + nrbufs) & (READ_KERN(legacy_pipe->buffers) - 1);
    } else {
        int head = READ_KERN(pipe->head);
        int ring_size = READ_KERN(pipe->ring_size);
        curbuf = (head - 1) & (ring_size - 1);
    }
#endif

    struct pipe_buffer *current_buffer = get_node_addr(bufs, curbuf);
    return current_buffer;
}

SEC("kprobe/do_splice")
TRACE_ENT_FUNC(do_splice, DIRTY_PIPE_SPLICE);

SEC("kretprobe/do_splice")
int BPF_KPROBE(trace_ret_do_splice)
{
    if (!should_submit(DIRTY_PIPE_SPLICE))
        return 0;

// The Dirty Pipe vulnerability exist in the kernel since version 5.8, so there is not use to do
// logic if version is too old. In non-CORE, it will even mean using defines which are not available
// in the kernel headers, which will cause bugs.
#if !defined(CORE) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
    return 0;
#else
    #ifdef CORE
    // Check if field of struct exist to determine kernel version - some fields change between
    // versions. In version 5.8 of the kernel, the field "high_zoneidx" changed its name to
    // "highest_zoneidx". This means that the existence of the field "high_zoneidx" can indicate
    // that the kernel version is lower than v5.8
    struct alloc_context *check_508;
    if (bpf_core_field_exists(check_508->high_zoneidx)) {
        return 0;
    }
    #endif // CORE

    args_t saved_args;
    if (load_args(&saved_args, DIRTY_PIPE_SPLICE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(DIRTY_PIPE_SPLICE);

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    // Catch only successful splice
    if ((int) PT_REGS_RC(ctx) <= 0) {
        return 0;
    }

    struct file *out_file = (struct file *) saved_args.args[2];
    struct pipe_inode_info *out_pipe = get_file_pipe_info(out_file);
    // Check that output is a pipe
    if (!out_pipe) {
        return 0;
    }

    // dirty_pipe_splice is a splice to a pipe which results that the last page copied could be
    // modified (the PIPE_BUF_CAN_MERGE flag is on in the pipe_buffer struct).
    struct pipe_buffer *last_write_page_buffer = get_last_write_pipe_buffer(out_pipe);
    unsigned int out_pipe_last_buffer_flags = READ_KERN(last_write_page_buffer->flags);
    if ((out_pipe_last_buffer_flags & PIPE_BUF_FLAG_CAN_MERGE) == 0) {
        return 0;
    }

    struct file *in_file = (struct file *) saved_args.args[0];
    struct inode *in_inode = READ_KERN(in_file->f_inode);
    u64 in_inode_number = READ_KERN(in_inode->i_ino);
    unsigned short in_file_type = READ_KERN(in_inode->i_mode) & S_IFMT;
    void *in_file_path = get_path_str(GET_FIELD_ADDR(in_file->f_path));
    size_t write_len = (size_t) saved_args.args[4];

    loff_t *off_in_addr = (loff_t *) saved_args.args[1];
    // In kernel v5.10 the pointer passed was no longer of the user, so flexibility is needed to
    // read it
    loff_t off_in;
    #ifndef CORE
        #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    off_in = READ_USER(*off_in_addr);
        #else
    off_in = READ_KERN(*off_in_addr);
        #endif
    #else  // CORE
    //
    // Check if field of struct exist to determine kernel version - some fields change between
    // versions. Field 'data' of struct 'public_key_signature' was introduced between v5.9 and
    // v5.10, so its existence might be used to determine whether the current version is older than
    // 5.9 or newer than 5.10.
    //
    // https://lore.kernel.org/stable/20210821203108.215937-1-rafaeldtinoco@gmail.com/
    //
    struct public_key_signature *check;
    if (!bpf_core_field_exists(check->data)) { // version < v5.10
        off_in = READ_USER(*off_in_addr);
    } else { // version >= v5.10
        off_in = READ_KERN(*off_in_addr);
    }
    #endif // CORE

    struct inode *out_inode = READ_KERN(out_file->f_inode);
    u64 out_inode_number = READ_KERN(out_inode->i_ino);

    // Only last page written to pipe is vulnerable from the end of written data
    loff_t next_exposed_data_offset_in_out_pipe_last_page =
        READ_KERN(last_write_page_buffer->offset) + READ_KERN(last_write_page_buffer->len);
    size_t in_file_size = READ_KERN(in_inode->i_size);
    size_t exposed_data_len = (PAGE_SIZE - 1) - next_exposed_data_offset_in_out_pipe_last_page;
    loff_t current_file_offset = off_in + write_len;
    if (current_file_offset + exposed_data_len > in_file_size) {
        exposed_data_len = in_file_size - current_file_offset - 1;
    }

    save_to_submit_buf(&data, &in_inode_number, sizeof(u64), 0);
    save_to_submit_buf(&data, &in_file_type, sizeof(unsigned short), 1);
    save_str_to_buf(&data, in_file_path, 2);
    save_to_submit_buf(&data, &current_file_offset, sizeof(loff_t), 3);
    save_to_submit_buf(&data, &exposed_data_len, sizeof(size_t), 4);
    save_to_submit_buf(&data, &out_inode_number, sizeof(u64), 5);
    save_to_submit_buf(&data, &out_pipe_last_buffer_flags, sizeof(unsigned int), 6);

    return events_perf_submit(&data, DIRTY_PIPE_SPLICE, 0);
#endif     // CORE && Version < 5.8
}

SEC("kprobe/do_init_module")
int BPF_KPROBE(trace_do_init_module)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    kmod_data_t module_data = {0};

    // get pointers before init
    struct module *mod = (struct module *) PT_REGS_PARM1(ctx);
    struct list_head ls = READ_KERN(mod->list);
    struct list_head *prev = ls.prev;
    struct list_head *next = ls.next;

    module_data.prev = (u64) prev;
    module_data.next = (u64) next;

    // save string values on buffer for kretprobe
    bpf_probe_read_str(&module_data.name, MODULE_NAME_LEN, (void *) READ_KERN(mod->name));
    bpf_probe_read_str(
        &module_data.version, MODULE_VERSION_MAX_LENGTH, (void *) READ_KERN(mod->version));
    bpf_probe_read_str(
        &module_data.srcversion, MODULE_SRCVERSION_MAX_LENGTH, (void *) READ_KERN(mod->srcversion));

    // save module_data for kretprobe
    bpf_map_update_elem(&module_init_map, &data.context.task.host_tid, &module_data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_init_module")
int BPF_KPROBE(trace_ret_do_init_module)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    kmod_data_t *orig_module_data =
        bpf_map_lookup_elem(&module_init_map, &data.context.task.host_tid);
    if (orig_module_data == NULL) {
        return 0;
    }

    // get next of original previous
    struct list_head *orig_prev_ptr = (struct list_head *) (orig_module_data->prev);
    u64 orig_prev_next_addr = (u64) READ_KERN(orig_prev_ptr->next);
    // get previous of original next
    struct list_head *orig_next_ptr = (struct list_head *) (orig_module_data->next);
    u64 orig_next_prev_addr = (u64) READ_KERN(orig_next_ptr->prev);

    // save strings to buf
    save_str_to_buf(&data, &orig_module_data->name, 0);
    save_str_to_buf(&data, &orig_module_data->version, 1);
    save_str_to_buf(&data, &orig_module_data->srcversion, 2);
    // save pointers to buf
    save_to_submit_buf(&data, &(orig_module_data->prev), sizeof(u64), 3);
    save_to_submit_buf(&data, &(orig_module_data->next), sizeof(u64), 4);
    save_to_submit_buf(&data, &orig_prev_next_addr, sizeof(u64), 5);
    save_to_submit_buf(&data, &orig_next_prev_addr, sizeof(u64), 6);

    events_perf_submit(&data, DO_INIT_MODULE, 0);

    // delete module data from map after it was used
    bpf_map_delete_elem(&module_init_map, &data.context.task.host_tid);

    return 0;
}

SEC("kprobe/load_elf_phdrs")
int BPF_KPROBE(trace_load_elf_phdrs)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace((&data)))
        return 0;

    file_id_t elf = {};
    struct file *loaded_elf = (struct file *) PT_REGS_PARM2(ctx);
    const char *elf_pathname = (char *) get_path_str(GET_FIELD_ADDR(loaded_elf->f_path));
    bpf_probe_read_str(elf.pathname, sizeof(elf.pathname), elf_pathname);
    elf.device = get_dev_from_file(loaded_elf);
    elf.inode = get_inode_nr_from_file(loaded_elf);

    bpf_map_update_elem(&interpreter_map, &data.context.task.host_tid, &elf, BPF_ANY);

    if (should_submit(LOAD_ELF_PHDRS)) {
        save_str_to_buf(&data, (void *) elf_pathname, 0);
        save_to_submit_buf(&data, &elf.device, sizeof(dev_t), 1);
        save_to_submit_buf(&data, &elf.inode, sizeof(unsigned long), 2);

        events_perf_submit(&data, LOAD_ELF_PHDRS, 0);
    }

    return 0;
}

SEC("kprobe/security_file_permission")
int BPF_KPROBE(trace_security_file_permission)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == NULL)
        return 0;
    struct inode *f_inode = get_inode_from_file(file);
    struct super_block *i_sb = get_super_block_from_inode(f_inode);
    unsigned long s_magic = get_s_magic_from_super_block(i_sb);

    // Only check procfs entries
    if (s_magic != PROC_SUPER_MAGIC) {
        return 0;
    }

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data))
        return 0;

    struct file_operations *fops = (struct file_operations *) READ_KERN(f_inode->i_fop);
    if (fops == NULL)
        return 0;

    unsigned long iterate_shared_addr = (unsigned long) READ_KERN(fops->iterate_shared);
    unsigned long iterate_addr = (unsigned long) READ_KERN(fops->iterate);
    if (iterate_addr == 0 && iterate_shared_addr == 0)
        return 0;

    unsigned long fops_addresses[3] = {(unsigned long) fops, iterate_shared_addr, iterate_addr};

    save_u64_arr_to_buf(&data, (const u64 *) fops_addresses, 3, 0);
    events_perf_submit(&data, HOOKED_PROC_FOPS, 0);
    return 0;
}

SEC("raw_tracepoint/task_rename")
int tracepoint__task__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (!should_trace((&data)))
        return 0;

    struct task_struct *tsk = (struct task_struct *) ctx->args[0];
    char old_name[TASK_COMM_LEN];
    bpf_probe_read_str(&old_name, TASK_COMM_LEN, tsk->comm);
    const char *new_name = (const char *) ctx->args[1];

    save_str_to_buf(&data, (void *) old_name, 0);
    save_str_to_buf(&data, (void *) new_name, 1);
    if ((data.config->options & OPT_SHOW_SYSCALL) && (data.task_info->syscall_traced)) {
        syscall_data_t *sys = &data.task_info->syscall_data;
        save_to_submit_buf(&data, (void *) &sys->id, sizeof(int), 2);
    }

    return events_perf_submit(&data, TASK_RENAME, 0);
}

static __always_inline bool
skb_revalidate_data(struct __sk_buff *skb, uint8_t **head, uint8_t **tail, const u32 offset)
{
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *) (long) skb->data;
        *tail = (uint8_t *) (long) skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}

// decide network event_id based on created net_packet_t
static __always_inline void set_net_event_id(net_packet_t *pkt)
{
    enum ports
    {
        DNS = 53,
    };

    if (pkt->dst_port == DNS)
        pkt->event_id = DNS_REQUEST;
    if (pkt->src_port == DNS)
        pkt->event_id = DNS_RESPONSE;
}

// some network events might need payload (even without capture)
static __always_inline bool should_submit_payload(net_packet_t *pkt)
{
    switch (pkt->event_id) {
        case DNS_REQUEST:
        case DNS_RESPONSE:
            return true;
        default:
            return false;
    }
}

static __always_inline int tc_probe(struct __sk_buff *skb, bool ingress)
{
    // Note: if we are attaching to docker0 bridge, the ingress bool argument is actually egress
    uint8_t *head = (uint8_t *) (long) skb->data;
    uint8_t *tail = (uint8_t *) (long) skb->data_end;

    if (head + sizeof(struct ethhdr) > tail)
        return TC_ACT_UNSPEC;

    struct ethhdr *eth = (void *) head;
    net_packet_t pkt = {0};
    pkt.event_id = NET_PACKET;
    pkt.ts = bpf_ktime_get_ns();
    pkt.len = skb->len;
    pkt.ifindex = skb->ifindex;
    net_id_t connect_id = {0};

    uint32_t l4_hdr_off;

    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_IP:
            l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off))
                return TC_ACT_UNSPEC;

            // create a IPv4-Mapped IPv6 Address
            struct iphdr *ip = (void *) head + sizeof(struct ethhdr);
            pkt.src_addr.s6_addr32[3] = ip->saddr;
            pkt.dst_addr.s6_addr32[3] = ip->daddr;
            pkt.src_addr.s6_addr16[5] = 0xffff;
            pkt.dst_addr.s6_addr16[5] = 0xffff;
            pkt.protocol = ip->protocol;
            break;

        case ETH_P_IPV6:
            l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off))
                return TC_ACT_UNSPEC;

            struct ipv6hdr *ip6 = (void *) head + sizeof(struct ethhdr);
            pkt.src_addr = ip6->saddr;
            pkt.dst_addr = ip6->daddr;
            pkt.protocol = ip6->nexthdr;
            break;

        default:
            return TC_ACT_UNSPEC;
    }

    switch (pkt.protocol) {
        case IPPROTO_TCP:
            if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off + sizeof(struct tcphdr)))
                return TC_ACT_UNSPEC;

            struct tcphdr *tcp = (void *) head + l4_hdr_off;
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;

        case IPPROTO_UDP:
            if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off + sizeof(struct udphdr)))
                return TC_ACT_UNSPEC;

            struct udphdr *udp = (void *) head + l4_hdr_off;
            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
            break;

        case IPPROTO_ICMP:
            if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off + sizeof(struct icmphdr)))
                return TC_ACT_UNSPEC;

            struct icmphdr *icmph = (void *) head + l4_hdr_off;
            u16 icmp_id = icmph->un.echo.id;
            pkt.src_port = icmp_id; // icmp_id so connect_id can be found
            pkt.dst_port = icmp_id; // icmp_id so connect_id can be found
            break;

        case IPPROTO_ICMPV6:
            if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off + sizeof(struct icmp6hdr)))
                return TC_ACT_UNSPEC;

            struct icmp6hdr *icmp6h = (void *) head + l4_hdr_off;
            u16 icmp6_id = icmp6h->icmp6_dataun.u_echo.identifier;
            pkt.src_port = icmp6_id; // icmp6_id so connect_id can be found
            pkt.dst_port = icmp6_id; // icmp6_id so connect_id can be found
            break;

        default:
            return TC_ACT_UNSPEC; // TODO: support more protocols
    }

    connect_id.protocol = pkt.protocol;
    connect_id.address = pkt.src_addr;
    connect_id.port = pkt.src_port;
    net_ctx_t *net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
    if (net_ctx == NULL) {
        // We could have used traffic direction (ingress bool) to know if we should look for src or
        // dst, however, if we attach to a bridge interface, src and dst are switched. For this
        // reason, we look in the network map for both src and dst
        connect_id.address = pkt.dst_addr;
        connect_id.port = pkt.dst_port;
        net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
        if (net_ctx == NULL) {
            // Check if network_map has an ip of 0.0.0.0. Note: A conflict might occur between
            // processes in different namespace that bind to 0.0.0.0
            // TODO: handle network namespaces conflicts
            __builtin_memset(connect_id.address.s6_addr, 0, sizeof(connect_id.address.s6_addr));
            eth = (void *) head;
            if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
                connect_id.address.s6_addr16[5] = 0xffff;
            net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
            if (net_ctx == NULL) {
                connect_id.port = pkt.src_port;
                net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
                if (net_ctx == NULL) {
                    return TC_ACT_UNSPEC;
                }
            }
        }
    }

    pkt.host_tid = net_ctx->host_tid;
    __builtin_memcpy(pkt.comm, net_ctx->comm, TASK_COMM_LEN);

    // if net_packet event not chosen, send minimal data only:
    //     timestamp (u64)      8 bytes
    //     net event_id (u32)   4 bytes
    //     host_id (u32)        4 bytes
    //     comm (char[])       16 bytes
    //     packet len (u32)     4 bytes
    //     ifindex (u32)        4 bytes
    size_t pkt_size = PACKET_MIN_SIZE;

    int iface_conf = get_iface_config(skb->ifindex);
    if (iface_conf & TRACE_IFACE) {
        pkt_size = sizeof(pkt);
        pkt.src_port = __bpf_ntohs(pkt.src_port);
        pkt.dst_port = __bpf_ntohs(pkt.dst_port);
        set_net_event_id(&pkt);
    }

    // The tc perf_event_output handler will use the upper 32 bits of the flags argument as a number
    // of bytes to include of the packet payload in the event data. If the size is too big, the call
    // to bpf_perf_event_output will fail and return -EFAULT.
    //
    // See bpf_skb_event_output in net/core/filter.c.
    u64 flags = BPF_F_CURRENT_CPU;

    if (iface_conf & CAPTURE_IFACE || should_submit_payload(&pkt))
        flags |= (u64) skb->len << 32;

    bpf_perf_event_output(skb, &net_events, flags, &pkt, pkt_size);

    return TC_ACT_UNSPEC;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return tc_probe(skb, false);
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return tc_probe(skb, true);
}

char LICENSE[] SEC("license") = "GPL";
#ifndef CORE
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
#endif
