// +build ignore

/*
Note: This file is licenced differently from the rest of the project
SPDX-License-Identifier: GPL-2.0
Copyright (C) Aqua Security inc.
*/

#ifndef CORE
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
//CO:RE is enabled
#include <vmlinux.h>
#include <missing_definitions.h>

#endif

#undef container_of
#include <bpf_core_read.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx)  ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

#define MAX_PERCPU_BUFSIZE              (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE                 4096      // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE              4096      // max size of bytes array (arbitrarily chosen)
#define MAX_STACK_ADDRESSES             1024      // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH                 20        // max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE             16        // bounded to size of the compared values (comm)
#define FILE_MAGIC_HDR_SIZE             32        // magic_write: bytes to save from a file's header
#define FILE_MAGIC_MASK                 31        // magic_write: mask used for verifier boundaries

#define SUBMIT_BUF_IDX                  0
#define STRING_BUF_IDX                  1
#define FILE_BUF_IDX                    2
#define MAX_BUFFERS                     3

#define SEND_VFS_WRITE                  1
#define SEND_MPROTECT                   2
#define SEND_KERNEL_MODULE              3
#define SEND_META_SIZE                  24

#define ALERT_MMAP_W_X                  1
#define ALERT_MPROT_X_ADD               2
#define ALERT_MPROT_W_ADD               3
#define ALERT_MPROT_W_REM               4

#define TAIL_VFS_WRITE                  0
#define TAIL_VFS_WRITEV                 1
#define TAIL_SEND_BIN                   2
#define TAIL_SEND_BIN_TP                3
#define MAX_TAIL_CALL                   4

#define NONE_T                          0UL
#define INT_T                           1UL
#define UINT_T                          2UL
#define LONG_T                          3UL
#define ULONG_T                         4UL
#define OFF_T_T                         5UL
#define MODE_T_T                        6UL
#define DEV_T_T                         7UL
#define SIZE_T_T                        8UL
#define POINTER_T                       9UL
#define STR_T                           10UL
#define STR_ARR_T                       11UL
#define SOCKADDR_T                      12UL
#define BYTES_T                         13UL
#define U16_T                           14UL
#define CRED_T                          15UL
#define INT_ARR_2_T                     16UL
#define TYPE_MAX                        255UL

#if defined(bpf_target_x86)
#define SYS_MMAP                        9
#define SYS_MPROTECT                    10
#define SYS_RT_SIGRETURN                15
#define SYS_EXECVE                      59
#define SYS_EXIT                        60
#define SYS_EXIT_GROUP                  231
#define SYS_EXECVEAT                    322
#define SYSCALL_CONNECT                 42
#define SYSCALL_ACCEPT                  43
#define SYSCALL_ACCEPT4                 288
#define SYSCALL_LISTEN                  50
#define SYSCALL_BIND                    49
#define SYSCALL_SOCKET                  41
#define SYS_DUP                         32
#define SYS_DUP2                        33
#define SYS_DUP3                        292
#elif defined(bpf_target_arm64)
#define SYS_MMAP                        222
#define SYS_MPROTECT                    226
#define SYS_RT_SIGRETURN                139
#define SYS_EXECVE                      221
#define SYS_EXIT                        93
#define SYS_EXIT_GROUP                  94
#define SYS_EXECVEAT                    281
#define SYSCALL_CONNECT                 203
#define SYSCALL_ACCEPT                  202
#define SYSCALL_ACCEPT4                 242
#define SYSCALL_LISTEN                  201
#define SYSCALL_BIND                    200
#define SYSCALL_SOCKET                  198
#define SYS_DUP                         23
#define SYS_DUP2                        1000      // undefined in arm64
#define SYS_DUP3                        24
#endif


#define NET_PACKET                      1000
#define DEBUG_NET_SECURITY_BIND         1001
#define DEBUG_NET_UDP_SENDMSG           1002
#define DEBUG_NET_UDP_DISCONNECT        1003
#define DEBUG_NET_UDP_DESTROY_SOCK      1004
#define DEBUG_NET_UDPV6_DESTROY_SOCK    1005
#define DEBUG_NET_INET_SOCK_SET_STATE   1006
#define DEBUG_NET_TCP_CONNECT           1007
#define MAX_NET_EVENT_ID                1008

#define RAW_SYS_ENTER                   MAX_NET_EVENT_ID +0
#define RAW_SYS_EXIT                    MAX_NET_EVENT_ID +1
#define SCHED_PROCESS_FORK              MAX_NET_EVENT_ID +2
#define SCHED_PROCESS_EXEC              MAX_NET_EVENT_ID +3
#define SCHED_PROCESS_EXIT              MAX_NET_EVENT_ID +4
#define SCHED_SWITCH                    MAX_NET_EVENT_ID +5
#define DO_EXIT                         MAX_NET_EVENT_ID +6
#define CAP_CAPABLE                     MAX_NET_EVENT_ID +7
#define VFS_WRITE                       MAX_NET_EVENT_ID +8
#define VFS_WRITEV                      MAX_NET_EVENT_ID +9
#define MEM_PROT_ALERT                  MAX_NET_EVENT_ID +10
#define COMMIT_CREDS                    MAX_NET_EVENT_ID +11
#define SWITCH_TASK_NS                  MAX_NET_EVENT_ID +12
#define MAGIC_WRITE                     MAX_NET_EVENT_ID +13
#define CGROUP_ATTACH_TASK              MAX_NET_EVENT_ID +14
#define CGROUP_MKDIR                    MAX_NET_EVENT_ID +15
#define CGROUP_RMDIR                    MAX_NET_EVENT_ID +16
#define SECURITY_BPRM_CHECK             MAX_NET_EVENT_ID +17
#define SECURITY_FILE_OPEN              MAX_NET_EVENT_ID +18
#define SECURITY_INODE_UNLINK           MAX_NET_EVENT_ID +19
#define SECURITY_SOCKET_CREATE          1028
#define SECURITY_SOCKET_LISTEN          1029
#define SECURITY_SOCKET_CONNECT         1030
#define SECURITY_SOCKET_ACCEPT          1031
#define SECURITY_SOCKET_BIND            1032
#define SECURITY_SB_MOUNT               1033
#define SECURITY_BPF                    1034
#define SECURITY_BPF_MAP                1035
#define SECURITY_KERNEL_READ_FILE       1036
#define SECURITY_INODE_MKNOD            1037
#define SECURITY_POST_READ_FILE         1038
#define SOCKET_DUP                      1039
#define HIDDEN_INODES                   1040
#define MAX_EVENT_ID                    1041


#define CONFIG_SHOW_SYSCALL             1
#define CONFIG_EXEC_ENV                 2
#define CONFIG_CAPTURE_FILES            3
#define CONFIG_EXTRACT_DYN_CODE         4
#define CONFIG_TRACEE_PID               5
#define CONFIG_CAPTURE_STACK_TRACES     6
#define CONFIG_UID_FILTER               7
#define CONFIG_MNT_NS_FILTER            8
#define CONFIG_PID_NS_FILTER            9
#define CONFIG_UTS_NS_FILTER            10
#define CONFIG_COMM_FILTER              11
#define CONFIG_PID_FILTER               12
#define CONFIG_CONT_FILTER              13
#define CONFIG_FOLLOW_FILTER            14
#define CONFIG_NEW_PID_FILTER           15
#define CONFIG_NEW_CONT_FILTER          16
#define CONFIG_DEBUG_NET                17
#define CONFIG_PROC_TREE_FILTER         18
#define CONFIG_CAPTURE_MODULES          19
#define CONFIG_CGROUP_V1                20
#define CONFIG_CGROUP_ID_FILTER         21

// get_config(CONFIG_XXX_FILTER) returns 0 if not enabled
#define FILTER_IN                       1
#define FILTER_OUT                      2

#define UID_LESS                        0
#define UID_GREATER                     1
#define PID_LESS                        2
#define PID_GREATER                     3
#define MNTNS_LESS                      4
#define MNTNS_GREATER                   5
#define PIDNS_LESS                      6
#define PIDNS_GREATER                   7

#define LESS_NOT_SET                    0
#define GREATER_NOT_SET                 ULLONG_MAX

#define DEV_NULL_STR                    0

#define CONT_ID_LEN                     12
#define CONT_ID_MIN_FULL_LEN            64

#define CONTAINER_EXISTED               1         // container existed before tracee was started
#define CONTAINER_CREATED               2         // new cgroup path created
#define CONTAINER_STARTED               3         // a process in the cgroup executed a new binary

#ifndef CORE
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)  // lower values in old kernels (instr lim is 4096)
#define MAX_STR_ARR_ELEM                40
#define MAX_ARGS_STR_ARR_ELEM           15
#define MAX_PATH_PREF_SIZE              64
#define MAX_PATH_COMPONENTS             20
#define MAX_BIN_CHUNKS                  110
#else                                             // complexity limit of 1M verified instructions
#define MAX_STR_ARR_ELEM                128
#define MAX_ARGS_STR_ARR_ELEM           128
#define MAX_PATH_PREF_SIZE              128
#define MAX_PATH_COMPONENTS             48
#define MAX_BIN_CHUNKS                  256
#endif
#else // CORE
#define MAX_STR_ARR_ELEM                40        // TODO: turn this into global variables set w/ libbpfgo
#define MAX_ARGS_STR_ARR_ELEM           15
#define MAX_PATH_PREF_SIZE              64
#define MAX_PATH_COMPONENTS             20
#define MAX_BIN_CHUNKS                  110
#endif

/*================================ eBPF KCONFIGs =============================*/

#ifdef CORE
#define get_kconfig(x) get_kconfig_val(x)
#else
#define get_kconfig(x) CONFIG_##x
#endif

#define ARCH_HAS_SYSCALL_WRAPPER        1000U

/*================================ eBPF MAPS =================================*/

#ifndef CORE

#define GET_FIELD_ADDR(field) &field

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr);         \
        _val;                                                           \
    })

#else // CORE

#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read_user((void *)&_val, sizeof(_val), &ptr);          \
        _val;                                                           \
    })
#endif

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)     \
    struct bpf_map_def SEC("maps") _name = {                            \
        .type = _type,                                                  \
        .key_size = sizeof(_key_type),                                  \
        .value_size = sizeof(_value_type),                              \
        .max_entries = _max_entries,                                    \
    };

#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240)

#define BPF_LRU_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, 10240)

#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024)

// stack traces: the value is 1 big byte array of the stack addresses
#define BPF_STACK_TRACE(_name, _max_entries)                            \
    struct bpf_map_def SEC("maps") _name = {                            \
        .type = BPF_MAP_TYPE_STACK_TRACE,                               \
        .key_size = sizeof(u32),                                        \
        .value_size = sizeof(size_t) * MAX_STACK_DEPTH,                 \
        .max_entries = _max_entries,                                    \
    };

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

/*=============================== INTERNAL STRUCTS ===========================*/

typedef struct event_context {
    u64 ts;                        // Timestamp
    u64 cgroup_id;
    u32 pid;                       // PID as in the userspace term
    u32 tid;                       // TID as in the userspace term
    u32 ppid;                      // Parent PID as in the userspace term
    u32 host_pid;                  // PID in host pid namespace
    u32 host_tid;                  // TID in host pid namespace
    u32 host_ppid;                 // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 eventid;
    s64 retval;
    u32 stack_id;
    u16 processor_id;              // The ID of the processor which processed the event
    u8 argnum;
} context_t;

typedef struct process_context {
    u64 ts;                        // Timestamp
    u64 cgroup_id;
    u32 pid;                       // PID as in the userspace term
    u32 tid;                       // TID as in the userspace term
    u32 ppid;                      // Parent PID as in the userspace term
    u32 host_pid;                  // PID in host pid namespace
    u32 host_tid;                  // TID in host pid namespace
    u32 host_ppid;                 // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
} process_context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct syscall_data {
    uint id;                       // Current syscall id
    args_t args;                   // Syscall arguments
    unsigned long ts;              // Timestamp of syscall entry
    unsigned long ret;             // Syscall ret val. May be used by syscall exit tail calls.
} syscall_data_t;

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

typedef struct event_data {
    struct task_struct *task;
    context_t context;
    void *ctx;
    buf_t *submit_p;
    u32 buf_off;
} event_data_t;

// For a good summary about capabilities, see https://lwn.net/Articles/636533/
typedef struct slim_cred {
    uid_t  uid;                    // real UID of the task
    gid_t  gid;                    // real GID of the task
    uid_t  suid;                   // saved UID of the task
    gid_t  sgid;                   // saved GID of the task
    uid_t  euid;                   // effective UID of the task
    gid_t  egid;                   // effective GID of the task
    uid_t  fsuid;                  // UID for VFS ops
    gid_t  fsgid;                  // GID for VFS ops
    u32    user_ns;                // User Namespace of the event
    u32    securebits;             // SUID-less security management
    u64    cap_inheritable;        // caps our children can inherit
    u64    cap_permitted;          // caps we're permitted
    u64    cap_effective;          // caps we can actually use
    u64    cap_bset;               // capability bounding set
    u64    cap_ambient;            // Ambient capability set
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

typedef struct local_net_id {
    struct in6_addr address;
    u16 port;
    u16 protocol;
} local_net_id_t;

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

/*=============================== KERNEL STRUCTS =============================*/

#ifndef CORE
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
#endif

/*================================= MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                         // various configurations
BPF_HASH(kconfig_map, u32, u32);                        // kernel config variables
BPF_HASH(chosen_events_map, u32, u32);                  // events chosen by the user
BPF_HASH(traced_pids_map, u32, u32);                    // track traced pids
BPF_HASH(new_pids_map, u32, u32);                       // track processes of newly executed binaries
BPF_HASH(containers_map, u32, u8);                      // map cgroup id to container status {EXISTED, CREATED, STARTED}
BPF_HASH(args_map, u64, args_t);                        // persist args between function entry and return
BPF_HASH(syscall_data_map, u32, syscall_data_t);        // persist data during syscall execution
BPF_HASH(inequality_filter, u32, u64);                  // filter events by some uint field either by < or >
BPF_HASH(uid_filter, u32, u32);                         // filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, u32);                         // filter events by PID
BPF_HASH(mnt_ns_filter, u64, u32);                      // filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, u32);                      // filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, u32);          // filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, u32);            // filter events by command name
BPF_HASH(cgroup_id_filter, u32, u32);                   // filter events by cgroup id
BPF_HASH(bin_args_map, u64, bin_args_t);                // persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32);                   // map 32bit to 64bit syscalls
BPF_HASH(params_types_map, u32, u64);                   // encoded parameters types for event
BPF_HASH(process_tree_map, u32, u32);                   // filter events by the ancestry of the traced process
BPF_HASH(process_context_map, u32, process_context_t);  // holds the process_context data for every tid
BPF_LRU_HASH(sock_ctx_map, u64, net_ctx_ext_t);         // socket address to process context
BPF_LRU_HASH(network_map, local_net_id_t, net_ctx_t);   // network identifier to process context
BPF_ARRAY(file_filter, path_filter_t, 3);               // filter vfs_write events
BPF_ARRAY(string_store, path_filter_t, 1);              // store strings from userspace
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);             // percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // holds offsets to bufs respectively
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);              // store programs for tail calls
BPF_PROG_ARRAY(prog_array_tp, MAX_TAIL_CALL);           // store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);          // store programs for tail calls
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);           // store programs for tail calls
BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);  // store stack traces

/*================================== EVENTS ==================================*/

BPF_PERF_OUTPUT(events);                                // events submission
BPF_PERF_OUTPUT(file_writes);                           // file writes events submission
BPF_PERF_OUTPUT(net_events);                            // network events submission

/*================ KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace* mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    struct pid_namespace* pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace* uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

static __always_inline u32 get_ipc_ns_id(struct nsproxy *ns)
{
    struct ipc_namespace* ipc_ns = READ_KERN(ns->ipc_ns);
    return READ_KERN(ipc_ns->ns.inum);
}

static __always_inline u32 get_net_ns_id(struct nsproxy *ns)
{
    struct net* net_ns = READ_KERN(ns->net_ns);
    return READ_KERN(net_ns ->ns.inum);
}

static __always_inline u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    struct cgroup_namespace* cgroup_ns = READ_KERN(ns->cgroup_ns);
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0)) && !defined(CORE)
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

static __always_inline char * get_task_uts_name(struct task_struct *task)
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

static __always_inline u32 get_task_host_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

static __always_inline u32 get_task_host_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

static __always_inline struct task_struct * get_parent_task(struct task_struct *task)
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

static __always_inline const char * get_binprm_filename(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->filename);
}

static __always_inline const char * get_cgroup_dirname(struct cgroup *cgrp)
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
        struct kernfs_node___older_v55 *kn_old = (void *)kn;
        struct kernfs_node___rh8 *kn_rh8 = (void *)kn;

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

static __always_inline struct mm_struct* get_mm_from_task(struct task_struct *task)
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

static __always_inline int get_argc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->argc);
}

static __always_inline unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_start);
}

static __always_inline unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return READ_KERN(mm->env_end);
}

static __always_inline int get_envc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->envc);
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

static __always_inline unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return READ_KERN(vma->vm_flags);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

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

static __always_inline struct sock* get_socket_sock(struct socket *socket)
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
    bpf_probe_read(&protocol, 1, (void *)(&sock->sk_gso_max_segs) - 3);
#else
    // kernel 5.6
    protocol = READ_KERN(sock->sk_protocol);
#endif
#else // CORE
    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset)) {
        check = (struct sock___old *) sock;
        bpf_core_read(&protocol, 1, (void *)(&check->sk_gso_max_segs) - 3);
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
    bpf_probe_read((void *)&sk_state_own_impl, sizeof(sk_state_own_impl), (const void *)&sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo* get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct sockaddr_un get_unix_sock_addr(struct unix_sock *sock)
{
    struct unix_address* addr = READ_KERN(sock->addr);
    int len = READ_KERN(addr->len);
    struct sockaddr_un sockaddr = {};
    if (len <= sizeof(struct sockaddr_un)) {
        bpf_probe_read(&sockaddr, len, addr->name);
    }
    return sockaddr;
}

/*============================ HELPER FUNCTIONS ==============================*/

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

static __always_inline int get_config(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int get_kconfig_val(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&kconfig_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int init_context(context_t *context, struct task_struct *task)
{
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
    if (get_config(CONFIG_CGROUP_V1)) {
        context->cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        context->cgroup_id = bpf_get_current_cgroup_id();
    }

    context->ts = bpf_ktime_get_ns();
    context->argnum = 0;

    // Clean Stack Trace ID
    context->stack_id = 0;

    context->processor_id = (u16)bpf_get_smp_processor_id();

    return 0;
}

static __always_inline int init_event_data(event_data_t *data, void *ctx)
{
    data->task = (struct task_struct *)bpf_get_current_task();
    init_context(&data->context, data->task);
    data->ctx = ctx;
    data->buf_off = sizeof(context_t);
    int buf_idx = SUBMIT_BUF_IDX;
    data->submit_p = bpf_map_lookup_elem(&bufs, &buf_idx);
    if (data->submit_p == NULL)
        return 0;

    return 1;
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

static __always_inline int should_trace(context_t *context)
{
    if (get_config(CONFIG_FOLLOW_FILTER)) {
        if (bpf_map_lookup_elem(&traced_pids_map, &context->host_tid) != 0)
            // If the process is already in the traced_pids_map and follow was
            // chosen, don't check the other filters
            return 1;
    }

    // Don't monitor self
    if (get_config(CONFIG_TRACEE_PID) == context->host_pid) {
        return 0;
    }

    bool is_new_pid = bpf_map_lookup_elem(&new_pids_map, &context->host_tid) != 0;
    bool is_container = false;
    bool is_new_container = false;
    u32 cgroup_id_lsb = context->cgroup_id;
    u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);
    if (state != NULL) {
        if (*state != CONTAINER_CREATED)
            is_container = true;
        if (*state == CONTAINER_STARTED)
            is_new_container = true;
    }

    if (!bool_filter_matches(CONFIG_NEW_CONT_FILTER, is_new_container))
        return 0;

    if (!bool_filter_matches(CONFIG_NEW_PID_FILTER, is_new_pid))
        return 0;

    if (!bool_filter_matches(CONFIG_CONT_FILTER, is_container))
        return 0;

    if (!uint_filter_matches(CONFIG_UID_FILTER, &uid_filter, context->uid, UID_LESS, UID_GREATER))
        return 0;

    if (!uint_filter_matches(CONFIG_MNT_NS_FILTER, &mnt_ns_filter, context->mnt_id, MNTNS_LESS, MNTNS_GREATER))
        return 0;

    if (!uint_filter_matches(CONFIG_PID_NS_FILTER, &pid_ns_filter, context->pid_id, PIDNS_LESS, PIDNS_GREATER))
        return 0;

    if (!uint_filter_matches(CONFIG_PID_FILTER, &pid_filter, context->host_tid, PID_LESS, PID_GREATER))
        return 0;

    if (!equality_filter_matches(CONFIG_UTS_NS_FILTER, &uts_ns_filter, &context->uts_name))
        return 0;

    if (!equality_filter_matches(CONFIG_COMM_FILTER, &comm_filter, &context->comm))
        return 0;

    if (!equality_filter_matches(CONFIG_PROC_TREE_FILTER, &process_tree_map, &context->pid))
        return 0;

    if (!equality_filter_matches(CONFIG_CGROUP_ID_FILTER, &cgroup_id_filter, &cgroup_id_lsb))
        return 0;

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

static __always_inline int save_to_submit_buf(event_data_t *data, void *ptr, u32 size, u8 index)
{
// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    // If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - (size+1))
        return 0;

    // Save argument index
    volatile int buf_off = data->buf_off;
    data->submit_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off+1) <= MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Read into buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off+1]), size, ptr) == 0) {
            // We update buf_off only if all writes were successful
            data->buf_off += size+1;
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
    if (data->buf_off > MAX_PERCPU_BUFSIZE - (size+1+sizeof(int)))
        return 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;

    if ((data->buf_off+1) <= MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE - sizeof(int)) {
        // Save size to buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off+1]), sizeof(int), &size) != 0) {
            return 0;
        }
    }

    if ((data->buf_off+1+sizeof(int)) <= MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE) {
        // Read bytes into buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off+1+sizeof(int)]), size & (MAX_BYTES_ARR_SIZE-1), ptr) == 0) {
            // We update buf_off only if all writes were successful
            data->buf_off += size+1+sizeof(int);
            data->context.argnum++;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_str_to_buf(event_data_t *data, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]

    // If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off+1) <= MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Read into buffer
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off+1+sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
            // Satisfy validator for probe read
            if ((data->buf_off+1) > MAX_PERCPU_BUFSIZE - sizeof(int)) {
                return 0;
            }
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off+1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off+1;
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
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
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
    int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
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
    data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)] = elem_num;
    data->context.argnum++;
    return 1;
}

#define MAX_ARR_LEN 8192

// This helper saves null (0x00) delimited string array into buf
static __always_inline int save_args_str_arr_to_buf(event_data_t *data, const char *start, const char *end, int elem_num, u8 index)
{
    // Data saved to submit buf: [index][len][arg #][null delimited string array]

    if (start >= end)
        return 0;

    int len = end - start;
    if (len > (MAX_ARR_LEN - 1))
        len = MAX_ARR_LEN - 1;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off+1) > MAX_PERCPU_BUFSIZE - sizeof(int))
        return 0;

    // Save array length
    bpf_probe_read(&(data->submit_p->buf[data->buf_off+1]), sizeof(int), &len);

    // Satisfy validator for probe read
    if ((data->buf_off+5) > MAX_PERCPU_BUFSIZE - sizeof(int))
        return 0;

    // Save number of arguments
    bpf_probe_read(&(data->submit_p->buf[data->buf_off+5]), sizeof(int), &elem_num);

    // Satisfy validator for probe read
    if ((data->buf_off+9) > MAX_PERCPU_BUFSIZE - MAX_ARR_LEN)
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(data->submit_p->buf[data->buf_off+9]), len & (MAX_ARR_LEN - 1), start) == 0) {
        // We update buf_off only if all writes were successful
        data->buf_off += len+9;
        data->context.argnum++;
        return 1;
    }

    return 0;
}

static __always_inline void* get_path_str(struct path *path)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);

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
                bpf_probe_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        off = buf_off - len;

        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
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
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

static __always_inline void* get_dentry_path_str(struct dentry* dentry)
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
        unsigned int len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
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
    return &string_p->buf[buf_off];
}

static __always_inline int events_perf_submit(event_data_t *data, u32 id, long ret)
{
    data->context.eventid = id;
    data->context.retval = ret;

    // Get Stack trace
    if (get_config(CONFIG_CAPTURE_STACK_TRACES)) {
        int stack_id = bpf_get_stackid(data->ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            data->context.stack_id = stack_id;
        }
    }

    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(context_t), &data->context);

    // satisfy validator by setting buffer bounds
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE-1);
    void *output_data = data->submit_p->buf;
    return bpf_perf_event_output(data->ctx, &events, BPF_F_CURRENT_CPU, output_data, size);
}

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

#define DEC_ARG(n, enc_arg) ((enc_arg>>(8*n))&0xFF)

static __always_inline int save_args_to_submit_buf(event_data_t *data, u64 types, args_t *args)
{
    unsigned int i;
    unsigned int rc = 0;
    unsigned int arg_num = 0;
    short family = 0;

    if (types == 0)
        return 0;

    #pragma unroll
    for(i=0; i<6; i++)
    {
        int size = 0;
        u8 type = DEC_ARG(i, types);
        u8 index = i;
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
                rc = save_str_to_buf(data, (void *)args->args[i], index);
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
                    rc = save_to_submit_buf(data, (void*)(args->args[i]), size, index);
                } else {
                    rc = save_to_submit_buf(data, &family, sizeof(short), index);
                }
                break;
            case INT_ARR_2_T:
                size = sizeof(int[2]);
                rc = save_to_submit_buf(data, (void*)(args->args[i]), size, index);
                break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T) && (type != INT_ARR_2_T)) {
            rc = save_to_submit_buf(data, (void*)&(args->args[i]), size, index);
        }

        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

#define TRACE_ENT_FUNC(name, id)                                        \
int trace_##name(struct pt_regs *ctx)                                   \
{                                                                       \
    event_data_t data = {};                                             \
    if (!init_event_data(&data, ctx))                                   \
        return 0;                                                       \
                                                                        \
    if (!should_trace(&data.context))                                   \
        return 0;                                                       \
                                                                        \
    args_t args = {};                                                   \
    args.args[0] = PT_REGS_PARM1(ctx);                                  \
    args.args[1] = PT_REGS_PARM2(ctx);                                  \
    args.args[2] = PT_REGS_PARM3(ctx);                                  \
    args.args[3] = PT_REGS_PARM4(ctx);                                  \
    args.args[4] = PT_REGS_PARM5(ctx);                                  \
    args.args[5] = PT_REGS_PARM6(ctx);                                  \
                                                                        \
    return save_args(&args, id);                                        \
}

#define TRACE_RET_FUNC(name, id, types, ret)                            \
int trace_ret_##name(void *ctx)                                         \
{                                                                       \
    args_t args = {};                                                   \
    if (load_args(&args, id) != 0)                                      \
        return -1;                                                      \
    del_args(id);                                                       \
                                                                        \
    event_data_t data = {};                                             \
    if (!init_event_data(&data, ctx))                                   \
        return 0;                                                       \
                                                                        \
    if (!event_chosen(id))                                              \
        return 0;                                                       \
                                                                        \
    save_args_to_submit_buf(&data, types, &args);                       \
                                                                        \
    return events_perf_submit(&data, id, ret);                          \
}

static __always_inline int get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!peer) {
        net_details->local_address = get_inet_rcv_saddr(inet);
        net_details->local_port = bpf_ntohs(get_inet_num(inet));
        net_details->remote_address = get_inet_daddr(inet);
        net_details->remote_port = get_inet_dport(inet);
    }
    else {
        net_details->remote_address = get_inet_rcv_saddr(inet);
        net_details->remote_port = bpf_ntohs(get_inet_num(inet));
        net_details->local_address = get_inet_daddr(inet);
        net_details->local_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk, struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

static __always_inline int get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details, int peer)
{
    // inspired by 'inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)'
    // reference: https://elixir.bootlin.com/linux/latest/source/net/ipv6/af_inet6.c#L509

    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);

    struct in6_addr addr = {};
    addr = get_sock_v6_rcv_saddr(sk);
    if (ipv6_addr_any(&addr)){
        addr = get_ipv6_pinfo_saddr(np);
    }

    // the flowinfo field can be specified by the user to indicate a network
    // flow. how it is used by the kernel, or whether it is enforced to be
    // unique is not so obvious.  getting this value is only supported by the
    // kernel for outgoing packets using the 'struct ipv6_pinfo'.  in any case,
    // leaving it with value of 0 won't affect our representation of network
    // flows.
    net_details->flowinfo = 0;

    // the scope_id field can be specified by the user to indicate the network
    // interface from which to send a packet. this only applies for link-local
    // addresses, and is used only by the local kernel.  getting this value is
    // done by using the 'ipv6_iface_scope_id(const struct in6_addr *addr, int
    // iface)' function.  in any case, leaving it with value of 0 won't affect
    // our representation of network flows.
    net_details->scope_id = 0;

    if (peer) {
        net_details->local_address = get_sock_v6_daddr(sk);
        net_details->local_port = get_inet_dport(inet);
        net_details->remote_address = addr;
        net_details->remote_port = get_inet_sport(inet);
    }
    else {
        net_details->local_address = addr;
        net_details->local_port = get_inet_sport(inet);
        net_details->remote_address = get_sock_v6_daddr(sk);
        net_details->remote_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline int get_local_sockaddr_in_from_network_details(struct sockaddr_in *addr, net_conn_v4_t *net_details, u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->local_port;
    addr->sin_addr.s_addr = net_details->local_address;

    return 0;
}

static __always_inline int get_remote_sockaddr_in_from_network_details(struct sockaddr_in *addr, net_conn_v4_t *net_details, u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;

    return 0;
}

static __always_inline int get_local_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr, net_conn_v6_t *net_details, u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->local_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->local_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr, net_conn_v6_t *net_details, u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v4(struct sock *sk, local_net_id_t *connect_id, net_conn_v4_t *net_details, u16 family)
{
    connect_id->address.s6_addr32[3] = net_details->local_address;
    connect_id->address.s6_addr16[5] = 0xffff;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v6(struct sock *sk, local_net_id_t *connect_id, net_conn_v6_t *net_details, u16 family)
{
    connect_id->address = net_details->local_address;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

static __always_inline struct file *get_struct_file_from_fd(u64 fd_num)
{

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL) {
        return NULL;
    }
    struct files_struct *files = (struct files_struct *)READ_KERN(task->files);
    if (files == NULL) {
        return NULL;
    }
    struct fdtable *fdt = (struct fdtable *)READ_KERN(files->fdt);
    if (fdt == NULL) {
        return NULL;
    }
    struct file **fd = (struct file **)READ_KERN(fdt->fd);
    if (fd == NULL) {
        return NULL;
    }
    struct file *f = (struct file *)READ_KERN(fd[fd_num]);
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

/*============================== SYSCALL HOOKS ===============================*/

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long id)
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    syscall_data_t sys = {};
    sys.id = ctx->args[1];

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)) {
    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];

    if (is_x86_compat(data.task)) {
#if defined(bpf_target_x86)
        sys.args.args[0] = READ_KERN(regs->bx);
        sys.args.args[1] = READ_KERN(regs->cx);
        sys.args.args[2] = READ_KERN(regs->dx);
        sys.args.args[3] = READ_KERN(regs->si);
        sys.args.args[4] = READ_KERN(regs->di);
        sys.args.args[5] = READ_KERN(regs->bp);
#endif // bpf_target_x86
    } else {
        sys.args.args[0] = READ_KERN(PT_REGS_PARM1(regs));
        sys.args.args[1] = READ_KERN(PT_REGS_PARM2(regs));
        sys.args.args[2] = READ_KERN(PT_REGS_PARM3(regs));
#if defined(bpf_target_x86)
        // x86-64: r10 used instead of rcx (4th param to a syscall)
        sys.args.args[3] = READ_KERN(regs->r10);
#else
        sys.args.args[3] = READ_KERN(PT_REGS_PARM4(regs));
#endif
        sys.args.args[4] = READ_KERN(PT_REGS_PARM5(regs));
        sys.args.args[5] = READ_KERN(PT_REGS_PARM6(regs));
    }
} else {
    bpf_probe_read(sys.args.args, sizeof(6 * sizeof(u64)), (void *)ctx->args);
}

    if (is_compat(data.task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys.id);
        if (id_64 == 0)
            return 0;

        sys.id = *id_64;
    }

    if (!should_trace(&data.context))
        return 0;

    if (event_chosen(RAW_SYS_ENTER)) {
        save_to_submit_buf(&data, (void*)&sys.id, sizeof(int), 0);
        events_perf_submit(&data, RAW_SYS_ENTER, 0);
    }

    // exit, exit_group and rt_sigreturn syscalls don't return - don't save args for them
    if (sys.id != SYS_EXIT && sys.id != SYS_EXIT_GROUP && sys.id != SYS_RT_SIGRETURN) {
        // save syscall data
        sys.ts = data.context.ts;
        bpf_map_update_elem(&syscall_data_map, &data.context.host_tid, &sys, BPF_ANY);
    }

    // call syscall handler, if exists
    // enter tail calls should never delete saved args
    bpf_tail_call(ctx, &sys_enter_tails, sys.id);
    return 0;
}

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long ret)
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
#if defined(bpf_target_x86)
    int id = READ_KERN(regs->orig_ax);
#elif defined(bpf_target_arm64)
    int id = READ_KERN(regs->syscallno);
#endif

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (is_compat(data.task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // Successfully loading syscall data also means we should trace this event
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys)
        return 0;

    // Sanity check - we returned from the expected syscall this task was executing
    if (sys->id != id)
        return 0;

    if (event_chosen(RAW_SYS_EXIT)) {
        save_to_submit_buf(&data, (void*)&id, sizeof(int), 0);
        events_perf_submit(&data, RAW_SYS_EXIT, ret);
    }

    if (event_chosen(id)) {
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
            data.buf_off = sizeof(context_t);
            data.context.argnum = 0;
            save_args_to_submit_buf(&data, types, &sys->args);
            data.context.ts = sys->ts;
            events_perf_submit(&data, id, ret);
        }
    }

out:
    // call syscall handler, if exists
    sys->ret = ret;
    // exit tail calls should always delete args and retval before return
    bpf_tail_call(ctx, &sys_exit_tails, id);
    bpf_map_delete_elem(&syscall_data_map, &data.context.host_tid);
    return 0;
}

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys)
        return -1;

    if (!event_chosen(SYS_EXECVE))
        return 0;

    save_str_to_buf(&data, (void *)sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(&data, (const char *const *)sys->args.args[1] /*argv*/, 1);
    if (get_config(CONFIG_EXEC_ENV)) {
        save_str_arr_to_buf(&data, (const char *const *)sys->args.args[2] /*envp*/, 2);
    }

    return events_perf_submit(&data, SYS_EXECVE, 0);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys)
        return -1;

    if (!event_chosen(SYS_EXECVEAT))
        return 0;

    save_to_submit_buf(&data, (void*)&sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(&data, (void *)sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(&data, (const char *const *)sys->args.args[2] /*argv*/, 2);
    if (get_config(CONFIG_EXEC_ENV)) {
        save_str_arr_to_buf(&data, (const char *const *)sys->args.args[3] /*envp*/, 3);
    }
    save_to_submit_buf(&data, (void*)&sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_perf_submit(&data, SYS_EXECVEAT, 0);
}

static __always_inline int check_fd_type(u64 fd, u16 type)
{
    unsigned short i_mode = get_inode_mode_from_fd(fd);

    if ((i_mode & S_IFMT) == type) {
        return 1;
    }

    return 0;
}

static __always_inline int send_socket_dup(event_data_t *data, u64 oldfd, u64 newfd)
{
    if (!event_chosen(SOCKET_DUP))
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
    struct socket *socket_from_file = (struct socket *)READ_KERN(f->private_data);
    if (socket_from_file == NULL) {
        return -1;
    }

    struct sock *sk = get_socket_sock(socket_from_file);
    u16 family = get_sock_family(sk);
    if ( (family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in remote;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in), 2);
    }
    else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 remote;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in6), 2);
    }
    else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *)sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);

        save_to_submit_buf(data, &sockaddr, sizeof(struct sockaddr_un), 2);
    }

    return events_perf_submit(data, SOCKET_DUP, 0);
}

SEC("raw_tracepoint/sys_dup")
int sys_dup_exit_tail(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx)){
        return 0;
    }

    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys) {
        return -1;
    }

    if (sys->ret < 0) {
        // dup failed
        return 0;
    }

    if (sys->id == SYS_DUP) {
        // args.args[0]: oldfd
        // retval: newfd
        send_socket_dup(&data, sys->args.args[0], sys->ret);
    }
    else if (sys->id == SYS_DUP2 || sys->id == SYS_DUP3) {
        // args.args[0]: oldfd
        // args.args[1]: newfd
        // retval: retval
        send_socket_dup(&data, sys->args.args[0], sys->args.args[1]);
    }

    // delete syscall data before return
    bpf_map_delete_elem(&syscall_data_map, &data.context.host_tid);

    return 0;
}

/*================================ OTHER HOOKS ===============================*/

// include/trace/events/sched.h:
// TP_PROTO(struct task_struct *parent, struct task_struct *child)
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // Note: we don't place should_trace() here, so we can keep track of the cgroups in the system
    struct task_struct *parent = (struct task_struct*)ctx->args[0];
    struct task_struct *child = (struct task_struct*)ctx->args[1];

    // note: v5.4 verifier does not like using (process_context_t *) from &data->context
    process_context_t process = {};
    __builtin_memcpy(&process, &data.context, sizeof(process_context_t));
    process.tid = get_task_ns_pid(child);
    process.host_tid = get_task_host_pid(child);
    bpf_map_update_elem(&process_context_map, &process.host_tid, &process, BPF_ANY);

    int parent_pid = get_task_host_pid(parent);
    int child_pid = get_task_host_pid(child);

    int parent_tgid = get_task_host_tgid(parent);
    int child_tgid = get_task_host_tgid(child);

    // update process tree map if the parent has an entry
    int proc_tree_filter_set = get_config(CONFIG_PROC_TREE_FILTER);
    if (proc_tree_filter_set) {
        u32 *tgid_filtered = bpf_map_lookup_elem(&process_tree_map, &parent_tgid);
        if (tgid_filtered) {
            bpf_map_update_elem(&process_tree_map, &child_tgid, tgid_filtered, BPF_ANY);
        }
    }

    if (!should_trace(&data.context))
        return 0;

    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    bpf_map_update_elem(&traced_pids_map, &child_pid, &child_pid, BPF_ANY);
    if (get_config(CONFIG_NEW_PID_FILTER)) {
        bpf_map_update_elem(&new_pids_map, &child_pid, &child_pid, BPF_ANY);
    }

    if (event_chosen(SCHED_PROCESS_FORK)) {
        int parent_ns_pid = get_task_ns_pid(parent);
        int parent_ns_tgid = get_task_ns_tgid(parent);
        int child_ns_pid = get_task_ns_pid(child);
        int child_ns_tgid = get_task_ns_tgid(child);

        save_to_submit_buf(&data, (void*)&parent_pid, sizeof(int), 0);
        save_to_submit_buf(&data, (void*)&parent_ns_pid, sizeof(int), 1);
        save_to_submit_buf(&data, (void*)&parent_tgid, sizeof(int), 2);
        save_to_submit_buf(&data, (void*)&parent_ns_tgid, sizeof(int), 3);
        save_to_submit_buf(&data, (void*)&child_pid, sizeof(int), 4);
        save_to_submit_buf(&data, (void*)&child_ns_pid, sizeof(int), 5);
        save_to_submit_buf(&data, (void*)&child_tgid, sizeof(int), 6);
        save_to_submit_buf(&data, (void*)&child_ns_tgid, sizeof(int), 7);

        events_perf_submit(&data, SCHED_PROCESS_FORK, 0);
    }

    return 0;
}

// include/trace/events/sched.h:
//TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    process_context_t *process = (process_context_t*) &data.context;

    // Perform the following checks before should_trace() so we can filter by
    // newly created containers/processes.  We assume that a new container/pod
    // has started when a process of a newly created cgroup and mount ns
    // executed a binary
    u32 cgroup_id_lsb = data.context.cgroup_id;
    u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);
    if (state != NULL && *state == CONTAINER_CREATED) {
        u32 mntns = get_task_mnt_ns_id(data.task);
        struct task_struct *parent = get_parent_task(data.task);
        u32 parent_mntns = get_task_mnt_ns_id(parent);
        if (mntns != parent_mntns)
            *state = CONTAINER_STARTED;
    }

    if (get_config(CONFIG_NEW_PID_FILTER))
        bpf_map_update_elem(&new_pids_map, &data.context.host_tid, &data.context.host_tid, BPF_ANY);

    if (!should_trace(&data.context))
        return 0;

    // We passed all filters (in should_trace()) - add this pid to traced pids set
    bpf_map_update_elem(&traced_pids_map, &data.context.host_tid, &data.context.host_tid, BPF_ANY);
    bpf_map_update_elem(&process_context_map, &data.context.host_tid, process, BPF_ANY);

    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    if (bprm == NULL) {
        return -1;
    }

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD) {
        invoked_from_kernel = 1;
    }

    const char *filename = get_binprm_filename(bprm);

    struct file* file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);

    // bprm->mm is null at this point (set by begin_new_exec()), and task->mm
    // is already initialized
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

    unsigned short stdin_type = get_inode_mode_from_fd(0) & S_IFMT;

    // Note: Starting from kernel 5.9, there are two new interesting fields in
    // bprm that we should consider adding:
    //
    // 1. struct file *executable - which can be used to get the executable
    //                              name passed to an interpreter
    // 2. fdpath                  - generated filename for execveat (after
    //                              resolving dirfd)

    save_str_to_buf(&data, (void *)filename, 0);
    save_str_to_buf(&data, file_path, 1);
    save_args_str_arr_to_buf(&data, (void *)arg_start, (void *)arg_end, argc, 2);
    if (get_config(CONFIG_EXEC_ENV)) {
        save_args_str_arr_to_buf(&data, (void *)env_start, (void *)env_end, envc, 3);
    }
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 4);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 5);
    save_to_submit_buf(&data, &invoked_from_kernel, sizeof(int), 6);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 7);
    save_to_submit_buf(&data, &stdin_type, sizeof(unsigned short), 8);

    return events_perf_submit(&data, SCHED_PROCESS_EXEC, 0);
}

// include/trace/events/sched.h:
// TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // evaluate should_trace before removing this pid from the maps
    bool traced = should_trace(&data.context);

    // Remove this pid from all maps
    bpf_map_delete_elem(&traced_pids_map, &data.context.host_tid);
    bpf_map_delete_elem(&new_pids_map, &data.context.host_tid);
    bpf_map_delete_elem(&syscall_data_map, &data.context.host_tid);
    bpf_map_delete_elem(&process_context_map, &data.context.host_tid);

    int proc_tree_filter_set = get_config(CONFIG_PROC_TREE_FILTER);

    bool group_dead = false;
    struct task_struct *task = data.task;
    struct signal_struct *signal = READ_KERN(task->signal);
    atomic_t live = READ_KERN(signal->live);
    // This check could be true for multiple thread exits if the thread count was 0 when the hooks were triggered.
    // This could happen for example if the threads performed exit in different CPUs simultaneously.
    if (live.counter == 0) {
        group_dead = true;
        if (proc_tree_filter_set) {
            bpf_map_delete_elem(&process_tree_map, &data.context.host_pid);
        }
    }

    if (!traced)
        return 0;

    long exit_code = get_task_exit_code(data.task);

    save_to_submit_buf(&data, (void*)&exit_code, sizeof(long), 0);
    save_to_submit_buf(&data, (void*)&group_dead, sizeof(bool), 1);

    return events_perf_submit(&data, SCHED_PROCESS_EXIT, 0);
}

// include/trace/events/sched.h:
// TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next),
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    if (!event_chosen(SCHED_SWITCH))
        return 0;

    struct task_struct *prev = (struct task_struct*)ctx->args[1];
    struct task_struct *next = (struct task_struct*)ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(&data, (void*)&cpu, sizeof(int), 0);
    save_to_submit_buf(&data, (void*)&prev_pid, sizeof(int), 1);
    save_str_to_buf(&data, prev->comm, 2);
    save_to_submit_buf(&data, (void*)&next_pid, sizeof(int), 3);
    save_str_to_buf(&data, next->comm, 4);

    return events_perf_submit(&data, SCHED_SWITCH, 0);
}
SEC("kprobe/filldir64")
int BPF_KPROBE(trace_filldir64)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (!should_trace((&data.context)))
        return 0;

    char * process_name = (char *)PT_REGS_PARM2(ctx);
    unsigned long process_inode_number = (unsigned long) PT_REGS_PARM5(ctx);
    if (process_inode_number == 0)
    {
        save_str_to_buf(&data, process_name, 0);
        return events_perf_submit(&data, HIDDEN_INODES, 0);
    }
    return 0;
}
SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    long code = PT_REGS_PARM1(ctx);

    return events_perf_submit(&data, DO_EXIT, code);
}

// include/trace/events/cgroup.h:
// TP_PROTO(struct cgroup *dst_cgrp, const char *path, struct task_struct *task, bool threadgroup)
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    char *path = (char*)ctx->args[1];
    struct task_struct *task = (struct task_struct*)ctx->args[2];

    int pid = get_task_host_pid(task);
    char *comm = READ_KERN(task->comm);

    save_str_to_buf(&data, path, 0);
    save_str_to_buf(&data, comm, 1);
    save_to_submit_buf(&data, (void*)&pid, sizeof(int), 2);
    events_perf_submit(&data, CGROUP_ATTACH_TASK, 0);

    return 0;
}

// include/trace/events/cgroup.h:
// TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup*)ctx->args[0];
    char *path = (char*)ctx->args[1];

    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;
    // Assume this is a new container. If not, userspace code will delete this entry
    u8 state = CONTAINER_CREATED;
    bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);

    save_to_submit_buf(&data, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&data, path, 1);
    events_perf_submit(&data, CGROUP_MKDIR, 0);

    return 0;
}

// include/trace/events/cgroup.h:
// TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup*)ctx->args[0];
    char *path = (char*)ctx->args[1];

    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;
    bpf_map_delete_elem(&containers_map, &cgroup_id_lsb);

    save_to_submit_buf(&data, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&data, path, 1);
    events_perf_submit(&data, CGROUP_RMDIR, 0);

    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    struct file* file = get_file_ptr_from_bprm(bprm);
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

    if (!should_trace(&data.context))
        return 0;

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    save_str_to_buf(&data, file_path, 0);
    save_to_submit_buf(&data, (void*)GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 4);
    if (get_config(CONFIG_SHOW_SYSCALL)) {
        syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
        if (sys) {
            save_to_submit_buf(&data, (void*)&sys->id, sizeof(int), 5);
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

    if (!should_trace(&data.context))
        return 0;

    const char *dev_name = (const char *)PT_REGS_PARM1(ctx);
    struct path *path = (struct path *)PT_REGS_PARM2(ctx);
    const char *type = (const char *)PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long)PT_REGS_PARM4(ctx);

    void *path_str = get_path_str(path);

    save_str_to_buf(&data, (void *)dev_name, 0);
    save_str_to_buf(&data, path_str, 1);
    save_str_to_buf(&data, (void *)type, 2);
    save_to_submit_buf(&data, &flags, sizeof(unsigned long), 3);

    return events_perf_submit(&data, SECURITY_SB_MOUNT, 0);
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    //struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
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

    if (!should_trace(&data.context))
        return 0;

    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);
    struct cred *old = (struct cred *)get_task_real_cred(data.task);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    struct user_namespace* userns_old = READ_KERN(old->user_ns);
    struct user_namespace* userns_new = READ_KERN(new->user_ns);

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

    // Currently, (2021), there are ~40 capabilities in the Linux kernel which
    // are stored in an u32 array of length 2. This might change in the (not so
    // near) future as more capabilities will be added. For now, we use u64 to
    // store this array in one piece

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

    save_to_submit_buf(&data, (void*)&old_slim, sizeof(slim_cred_t), 0);
    save_to_submit_buf(&data, (void*)&new_slim, sizeof(slim_cred_t), 1);

    if ((old_slim.uid != new_slim.uid) ||
        (old_slim.gid != new_slim.gid) ||
        (old_slim.suid != new_slim.suid) ||
        (old_slim.sgid != new_slim.sgid) ||
        (old_slim.euid != new_slim.euid) ||
        (old_slim.egid != new_slim.egid) ||
        (old_slim.fsuid != new_slim.fsuid) ||
        (old_slim.fsgid != new_slim.fsgid) ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable) ||
        (old_slim.cap_permitted != new_slim.cap_permitted) ||
        (old_slim.cap_effective != new_slim.cap_effective) ||
        (old_slim.cap_bset != new_slim.cap_bset) ||
        (old_slim.cap_ambient != new_slim.cap_ambient)) {

        if (get_config(CONFIG_SHOW_SYSCALL)) {
            syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
            if (sys) {
                save_to_submit_buf(&data, (void*)&sys->id, sizeof(int), 2);
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

    if (!should_trace(&data.context))
        return 0;

    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct nsproxy *new = (struct nsproxy *)PT_REGS_PARM2(ctx);

    if (!new)
        return 0;

    pid_t pid = READ_KERN(task->pid);
    u32 old_mnt = data.context.mnt_id;
    u32 new_mnt = get_mnt_ns_id(new);
    u32 old_pid = data.context.pid_id;
    u32 new_pid = get_pid_ns_id(new);
    u32 old_uts = get_task_uts_ns_id(task);
    u32 new_uts = get_uts_ns_id(new);
    u32 old_ipc = get_task_ipc_ns_id(task);
    u32 new_ipc = get_ipc_ns_id(new);
    u32 old_net = get_task_net_ns_id(task);
    u32 new_net = get_net_ns_id(new);
    u32 old_cgroup = get_task_cgroup_ns_id(task);
    u32 new_cgroup = get_cgroup_ns_id(new);

    save_to_submit_buf(&data, (void*)&pid, sizeof(int), 0);

    if (old_mnt != new_mnt)
        save_to_submit_buf(&data, (void*)&new_mnt, sizeof(u32), 1);
    if (old_pid != new_pid)
        save_to_submit_buf(&data, (void*)&new_pid, sizeof(u32), 2);
    if (old_uts != new_uts)
        save_to_submit_buf(&data, (void*)&new_uts, sizeof(u32), 3);
    if (old_ipc != new_ipc)
        save_to_submit_buf(&data, (void*)&new_ipc, sizeof(u32), 4);
    if (old_net != new_net)
        save_to_submit_buf(&data, (void*)&new_net, sizeof(u32), 5);
    if (old_cgroup != new_cgroup)
        save_to_submit_buf(&data, (void*)&new_cgroup, sizeof(u32), 6);
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

    if (!should_trace(&data.context))
        return 0;

    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(&data, (void*)&cap, sizeof(int), 0);
    if (get_config(CONFIG_SHOW_SYSCALL)) {
        syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
        if (sys) {
            save_to_submit_buf(&data, (void*)&sys->id, sizeof(int), 1);
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

    if (!should_trace(&data.context))
        return 0;

    int family = (int)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM2(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);
    int kern = (int)PT_REGS_PARM4(ctx);

    save_to_submit_buf(&data, (void *)&family, sizeof(int), 0);
    save_to_submit_buf(&data, (void *)&type, sizeof(int), 1);
    save_to_submit_buf(&data, (void *)&protocol, sizeof(int), 2);
    save_to_submit_buf(&data, (void *)&kern, sizeof(int), 3);

    return events_perf_submit(&data, SECURITY_SOCKET_CREATE, 0);
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    int backlog = (int)PT_REGS_PARM2(ctx);

    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ( (family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the listen syscall (which eventually invokes this function)
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys || sys->id != SYSCALL_LISTEN)
        return 0;

    save_to_submit_buf(&data, (void *)&sys->args.args[0], sizeof(u32), 0);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *)&local, sizeof(struct sockaddr_in), 1);
    }
    else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *)&local, sizeof(struct sockaddr_in6), 1);
    }
    else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *)sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(&data, (void *)&sockaddr, sizeof(struct sockaddr_un), 1);
    }

    save_to_submit_buf(&data, (void *)&backlog, sizeof(int), 2);

    return events_perf_submit(&data, SECURITY_SOCKET_LISTEN, 0);
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    uint addr_len = (uint)PT_REGS_PARM3(ctx);

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ( (sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the connect syscall (which eventually invokes this function)
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys || sys->id != SYSCALL_CONNECT)
        return 0;

    save_to_submit_buf(&data, (void *)&sys->args.args[0], sizeof(u32), 0);

    if (sa_fam == AF_INET) {
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in), 1);
    }
    else if (sa_fam == AF_INET6) {
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in6), 1);
    }
    else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *)address);
            save_to_submit_buf(&data, (void *)&sockaddr, sizeof(struct sockaddr_un), 1);
        }
        else
#endif
            save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&data, SECURITY_SOCKET_CONNECT, 0);
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ( (family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the accept syscall (which eventually invokes this function)
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys || (sys->id != SYSCALL_ACCEPT && sys->id != SYSCALL_ACCEPT4))
        return 0;

    save_to_submit_buf(&data, (void *)&sys->args.args[0], sizeof(u32), 0);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *)&local, sizeof(struct sockaddr_in), 1);
    }
    else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(&data, (void *)&local, sizeof(struct sockaddr_in6), 1);
    }
    else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *)sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(&data, (void *)&sockaddr, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&data, SECURITY_SOCKET_ACCEPT, 0);
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    uint addr_len = (uint)PT_REGS_PARM3(ctx);

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ( (sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the bind syscall (which eventually invokes this function)
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys || sys->id != SYSCALL_BIND)
        return 0;

    save_to_submit_buf(&data, (void *)&sys->args.args[0], sizeof(u32), 0);

    u16 protocol = get_sock_protocol(sk);
    local_net_id_t connect_id = {0};
    connect_id.protocol = protocol;

    if (sa_fam == AF_INET) {
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in), 1);

        struct sockaddr_in *addr = (struct sockaddr_in *)address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin_port)){
            connect_id.address.s6_addr32[3] = READ_KERN(addr->sin_addr).s_addr;
            connect_id.address.s6_addr16[5] = 0xffff;
            connect_id.port = READ_KERN(addr->sin_port);
        }
    }
    else if (sa_fam == AF_INET6) {
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in6), 1);

        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin6_port)){
            connect_id.address = READ_KERN(addr->sin6_addr);
            connect_id.port = READ_KERN(addr->sin6_port);
        }
    }
    else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *)address);
            save_to_submit_buf(&data, (void *)&sockaddr, sizeof(struct sockaddr_un), 1);
        }
        else
#endif
            save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_un), 1);
    }

    if (connect_id.port) {
        net_ctx_t net_ctx;
        net_ctx.host_tid = data.context.host_tid;
        __builtin_memcpy(net_ctx.comm, data.context.comm, TASK_COMM_LEN);
        bpf_map_update_elem(&network_map, &connect_id, &net_ctx, BPF_ANY);
    }

    // netDebug event
    if (get_config(CONFIG_DEBUG_NET) && (sa_fam != AF_UNIX)) {
        net_debug_t debug_event = {0};
        debug_event.ts = data.context.ts;
        debug_event.host_tid = data.context.host_tid;
        __builtin_memcpy(debug_event.comm, data.context.comm, TASK_COMM_LEN);
        debug_event.event_id = DEBUG_NET_SECURITY_BIND;
        debug_event.local_addr = connect_id.address;
        debug_event.local_port = __bpf_ntohs(connect_id.port);
        debug_event.protocol = protocol;
        bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return events_perf_submit(&data, SECURITY_SOCKET_BIND, 0);
}

// To delete socket from net map use tid==0, otherwise, update
static __always_inline int net_map_update_or_delete_sock(void* ctx, int event_id, struct sock *sk, u32 tid)
{
    local_net_id_t connect_id = {0};
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

    // netDebug event
    if (get_config(CONFIG_DEBUG_NET)) {
        net_debug_t debug_event = {0};
        debug_event.ts = bpf_ktime_get_ns();
        debug_event.host_tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&debug_event.comm, sizeof(debug_event.comm));
        debug_event.event_id = event_id;
        debug_event.local_addr = connect_id.address;
        debug_event.local_port = __bpf_ntohs(connect_id.port);
        debug_event.protocol = connect_id.protocol;
        bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_SENDMSG, sk, data.context.host_tid);
}

SEC("kprobe/__udp_disconnect")
int BPF_KPROBE(trace_udp_disconnect)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_DISCONNECT, sk, 0);
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(trace_udp_destroy_sock)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_DESTROY_SOCK, sk, 0);
}

SEC("kprobe/udpv6_destroy_sock")
int BPF_KPROBE(trace_udpv6_destroy_sock)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDPV6_DESTROY_SOCK, sk, 0);
}

// include/trace/events/sock.h:
// TP_PROTO(const struct sock *sk, const int oldstate, const int newstate)
SEC("raw_tracepoint/inet_sock_set_state")
int tracepoint__inet_sock_set_state(struct bpf_raw_tracepoint_args *ctx)
{
    local_net_id_t connect_id = {0};
    net_debug_t debug_event = {0};
    net_ctx_ext_t net_ctx_ext = {0};

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    struct sock *sk = (struct sock *)ctx->args[0];
    int old_state = ctx->args[1];
    int new_state = ctx->args[2];

    // Sometimes the socket state may be changed by other contexts that handle
    // the tcp network stack (e.g. network driver). In these cases, we won't
    // pass the should_trace() check. To overcome this problem, we save the
    // socket pointer in sock_ctx_map in states that we observed to have the
    // correct context. We can then check for the existence of a socket in the
    // map, and continue if it was traced before.

    net_ctx_ext_t *sock_ctx_p = bpf_map_lookup_elem(&sock_ctx_map, &sk);
    if (!sock_ctx_p) {
        if (!should_trace(&data.context)) {
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
                net_ctx_ext.host_tid = data.context.host_tid;
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
        // At this point, port equals 0, so we will not be able to use current
        // connect_id as a key to network map.  We used the value saved in
        // sock_ctx_map instead.
        if (sock_ctx_p) {
            connect_id.port = sock_ctx_p->local_port;
        }
        bpf_map_delete_elem(&sock_ctx_map, &sk);
        bpf_map_delete_elem(&network_map, &connect_id);
        break;
    }

    // netDebug event
    if (get_config(CONFIG_DEBUG_NET)) {
        debug_event.ts = data.context.ts;
        if (!sock_ctx_p) {
            debug_event.host_tid = data.context.host_tid;
            bpf_get_current_comm(&debug_event.comm, sizeof(debug_event.comm));
        } else {
            debug_event.host_tid = sock_ctx_p->host_tid;
            __builtin_memcpy(debug_event.comm, sock_ctx_p->comm, TASK_COMM_LEN);
        }
        debug_event.event_id = DEBUG_NET_INET_SOCK_SET_STATE;
        debug_event.old_state = old_state;
        debug_event.new_state = new_state;
        debug_event.sk_ptr = (u64)sk;
        debug_event.protocol = connect_id.protocol;
        bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    local_net_id_t connect_id = {0};
    net_ctx_ext_t net_ctx_ext = {0};

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

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

    net_ctx_ext.host_tid = data.context.host_tid;
    bpf_get_current_comm(&net_ctx_ext.comm, sizeof(net_ctx_ext.comm));
    net_ctx_ext.local_port = connect_id.port;
    bpf_map_update_elem(&sock_ctx_map, &sk, &net_ctx_ext, BPF_ANY);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_TCP_CONNECT, sk, data.context.host_tid);
}

static __always_inline u32 send_bin_helper(void* ctx, struct bpf_map_def *prog_array, int tail_call)
{
    // Note: sending the data to the userspace have the following constraints:
    //
    // 1. We need a buffer that we know it's exact size (so we can send chunks
    //    of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data can be overridden if
    //    userspace doesn't consume it fast enough

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

#define F_SEND_TYPE   0
#define F_CGROUP_ID   (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF    (F_CGROUP_ID + sizeof(u64))
#define F_SZ_OFF      (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF     (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF   (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE  (MAX_PERCPU_BUFSIZE >> 1)

    bpf_probe_read((void **)&(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args->type);

    u64 cgroup_id;
    if (get_config(CONFIG_CGROUP_V1)) {
        cgroup_id = get_cgroup_v1_subsys0_id((struct task_struct *)bpf_get_current_task());
    } else {
        cgroup_id = bpf_get_current_cgroup_id();
    }
    bpf_probe_read((void **)&(file_buf_p->buf[F_CGROUP_ID]), sizeof(u64), &cgroup_id);

    // Save metadata to be used in filename
    bpf_probe_read((void **)&(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args->metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = bin_args->full_size/F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

    // Handle full chunks in loop
    #pragma unroll
    for (i = 0; i < MAX_BIN_CHUNKS; i++) {
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
        // Handle the rest of write recursively
        bin_args->full_size = chunk_size;
        bpf_tail_call(ctx, prog_array, tail_call);
        bpf_map_delete_elem(&bin_args_map, &id);
        return 0;
    }

    if (chunk_size) {
        // Save last chunk
        chunk_size = chunk_size & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
        bpf_probe_read((void **)&(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
        bpf_probe_read((void **)&(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
        bpf_probe_read((void **)&(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

        // Satisfy validator by setting buffer bounds
        int size = (F_CHUNK_OFF+chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
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
int send_bin_tp(void* ctx)
{
    return send_bin_helper(ctx, &prog_array_tp, TAIL_SEND_BIN_TP);
}

static __always_inline int do_vfs_write_writev(struct pt_regs *ctx, u32 event_id, u32 tail_call_id)
{
    args_t saved_args;
    if (load_args(&saved_args, event_id) != 0) {
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
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

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

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (event_chosen(VFS_WRITE) || event_chosen(VFS_WRITEV)) {
        save_str_to_buf(&data, file_path, 0);
        save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 1);
        save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 2);

        if (event_id == VFS_WRITE)
            save_to_submit_buf(&data, &count, sizeof(size_t), 3);
        else
            save_to_submit_buf(&data, &vlen, sizeof(unsigned long), 3);
        save_to_submit_buf(&data, &start_pos, sizeof(off_t), 4);

        // Submit vfs_write(v) event
        events_perf_submit(&data, event_id, PT_REGS_RC(ctx));
    }

    // magic_write event checks if the header of some file is changed
    if (event_chosen(MAGIC_WRITE) && !char_dev && (start_pos == 0)) {
        data.buf_off = sizeof(context_t);
        data.context.argnum = 0;

        u8 header[FILE_MAGIC_HDR_SIZE];

        save_str_to_buf(&data, file_path, 0);

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

        save_bytes_to_buf(&data, header, header_bytes, 1);
        save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 2);
        save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 3);

        // Submit magic_write event
        events_perf_submit(&data, MAGIC_WRITE, PT_REGS_RC(ctx));
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

    struct file *file      = (struct file *) saved_args.args[0];
    if (event_id == VFS_WRITE) {
        ptr                = (void*)         saved_args.args[1];
    } else {
        vec                = (struct iovec*) saved_args.args[1];
        vlen               =                 saved_args.args[2];
    }
    loff_t *pos            = (loff_t*)       saved_args.args[3];

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

        if (has_prefix(filter_p->path, (char*)&string_p->buf[*off], MAX_PATH_PREF_SIZE)) {
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
    u32 pid = data.context.pid;

    int idx = DEV_NULL_STR;
    path_filter_t *stored_str_p = bpf_map_lookup_elem(&string_store, &idx);
    if (stored_str_p == NULL)
        return -1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
        return -1;

    // check for /dev/null
    if (!has_prefix(stored_str_p->path, (char*)&string_p->buf[*off], 10))
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
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // Load the arguments given to the mmap syscall (which eventually invokes this function)
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys || sys->id != SYS_MMAP)
        return 0;

    if ((sys->args.args[2] & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC)) {
        u32 alert = ALERT_MMAP_W_X;
        save_to_submit_buf(&data, &alert, sizeof(u32), 0);
        events_perf_submit(&data, MEM_PROT_ALERT, 0);
    }

    return 0;
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_mprotect_alert)
{
    bin_args_t bin_args = {};

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    // Load the arguments given to the mprotect syscall (which eventually invokes this function)
    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys || sys->id != SYS_MPROTECT)
        return 0;

    struct vm_area_struct *vma = (struct vm_area_struct *)PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);
    //unsigned long prot = PT_REGS_PARM3(ctx);

    void *addr = (void*)sys->args.args[0];
    size_t len = sys->args.args[1];
    unsigned long prev_prot = get_vma_flags(vma);

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

    if ((prev_prot & VM_EXEC) && !(prev_prot & VM_WRITE)
        && ((reqprot & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC))) {
        u32 alert = ALERT_MPROT_W_ADD;
        save_to_submit_buf(&data, &alert, sizeof(u32), 0);
        return events_perf_submit(&data, MEM_PROT_ALERT, 0);
    }

    if (((prev_prot & (VM_WRITE|VM_EXEC)) == (VM_WRITE|VM_EXEC))
        && (reqprot & VM_EXEC) && !(reqprot & VM_WRITE)) {
        u32 alert = ALERT_MPROT_W_REM;
        save_to_submit_buf(&data, &alert, sizeof(u32), 0);
        events_perf_submit(&data, MEM_PROT_ALERT, 0);

        if (get_config(CONFIG_EXTRACT_DYN_CODE)) {
            bin_args.type = SEND_MPROTECT;
            bpf_probe_read(bin_args.metadata, sizeof(u64), &data.context.ts);
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

SEC("raw_tracepoint/sys_init_module")
int syscall__init_module(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    syscall_data_t *sys = bpf_map_lookup_elem(&syscall_data_map, &data.context.host_tid);
    if (!sys)
        return -1;

    bin_args_t bin_args = {};

    u32 pid = data.context.host_pid;
    u64 dummy = 0;
    void *addr = (void*)sys->args.args[0];
    unsigned long len = (unsigned long)sys->args.args[1];

    if (get_config(CONFIG_CAPTURE_MODULES)) {
        bin_args.type = SEND_KERNEL_MODULE;
        bpf_probe_read(bin_args.metadata, 4, &dummy);
        bpf_probe_read(&bin_args.metadata[4], 8, &dummy);
        bpf_probe_read(&bin_args.metadata[12], 4, &pid);
        bpf_probe_read(&bin_args.metadata[16], 8, &len);
        bin_args.ptr = (char *)addr;
        bin_args.start_off = 0;
        bin_args.full_size = (unsigned int)len;

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

    if (!should_trace(&data.context))
        return 0;

    int cmd = (int)PT_REGS_PARM1(ctx);

    // 1st argument == cmd (int)
    save_to_submit_buf(&data, (void *)&cmd, sizeof(int), 0);

    return events_perf_submit(&data, SECURITY_BPF, 0);
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(trace_security_bpf_map)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct bpf_map *map = (struct bpf_map *)PT_REGS_PARM1(ctx);

    // 1st argument == map_id (u32)
    save_to_submit_buf(&data, (void *)GET_FIELD_ADDR(map->id), sizeof(int), 0);
    // 2nd argument == map_name (const char *)
    save_str_to_buf(&data, (void *)GET_FIELD_ADDR(map->name), 1);

    return events_perf_submit(&data, SECURITY_BPF_MAP, 0);
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    struct file* file = (struct file*)PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id)PT_REGS_PARM2(ctx);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    save_str_to_buf(&data, file_path, 0);
    save_to_submit_buf(&data, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(&data, &inode_nr, sizeof(unsigned long), 2);
    save_to_submit_buf(&data, &type_id, sizeof(int), 3);

    return events_perf_submit(&data, SECURITY_KERNEL_READ_FILE, 0);
}

SEC("kprobe/security_kernel_post_read_file")
int BPF_KPROBE(trace_security_kernel_post_read_file)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    if (!should_trace(&data.context))
        return 0;

    bin_args_t bin_args = {};
    u64 id = bpf_get_current_pid_tgid();

    struct file* file = (struct file*)PT_REGS_PARM1(ctx);
    u32 pid = data.context.host_pid;

    char* buf = (char*)PT_REGS_PARM2(ctx);
    loff_t size = (loff_t)PT_REGS_PARM3(ctx);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id)PT_REGS_PARM4(ctx);

    // Send event if chosen
    if (event_chosen(SECURITY_POST_READ_FILE)) {
        void *file_path = get_path_str(&file->f_path);
        save_str_to_buf(&data, file_path, 0);
        save_to_submit_buf(&data, &size, sizeof(loff_t), 1);
        save_to_submit_buf(&data, &type_id, sizeof(int), 2);
        events_perf_submit(&data, SECURITY_POST_READ_FILE, 0);
    }

    if (get_config(CONFIG_CAPTURE_MODULES)) {
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

    if (!should_trace(&data.context))
        return 0;

    struct dentry* dentry = (struct dentry*)PT_REGS_PARM2(ctx);
    unsigned short mode = (unsigned short)PT_REGS_PARM3(ctx);
    unsigned int dev = (unsigned int)PT_REGS_PARM4(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(&data, dentry_path, 0);
    save_to_submit_buf(&data, &mode, sizeof(unsigned short), 1);
    save_to_submit_buf(&data, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&data, SECURITY_INODE_MKNOD, 0);
}

static __always_inline bool skb_revalidate_data(struct __sk_buff *skb, uint8_t **head, uint8_t **tail, const u32 offset) {
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}

static __always_inline int tc_probe(struct __sk_buff *skb, bool ingress) {
    // Note: if we are attaching to docker0 bridge, the ingress bool argument is actually egress
    uint8_t *head = (uint8_t *)(long)skb->data;
    uint8_t *tail = (uint8_t *)(long)skb->data_end;

    if (head + sizeof(struct ethhdr) > tail) {
        return TC_ACT_UNSPEC;
    }

    struct ethhdr *eth = (void *)head;
    net_packet_t pkt = {0};
    pkt.ts = bpf_ktime_get_ns();
    pkt.len = skb->len;
    pkt.event_id = NET_PACKET;
    pkt.ifindex = skb->ifindex;
    local_net_id_t connect_id = {0};

    uint32_t l4_hdr_off;

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);

        if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off)) {
            return TC_ACT_UNSPEC;
        }

        struct iphdr *ip = (void *)head + sizeof(struct ethhdr);

        // Create a IPv4-Mapped IPv6 Address
        pkt.src_addr.s6_addr32[3] = ip->saddr;
        pkt.dst_addr.s6_addr32[3] = ip->daddr;

        pkt.src_addr.s6_addr16[5] = 0xffff;
        pkt.dst_addr.s6_addr16[5] = 0xffff;

        pkt.protocol = ip->protocol;

        break;
    case ETH_P_IPV6:
        l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

        if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off)) {
            return TC_ACT_UNSPEC;
        }

        struct ipv6hdr *ip6 = (void *)head + sizeof(struct ethhdr);

        pkt.src_addr = ip6->saddr;
        pkt.dst_addr = ip6->daddr;

        pkt.protocol = ip6->nexthdr;

        break;
    default:
        return TC_ACT_UNSPEC;
    }

    if (pkt.protocol == IPPROTO_TCP) {
        if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off + sizeof(struct tcphdr))) {
            return TC_ACT_UNSPEC;
        }

        struct tcphdr *tcp = (void *)head + l4_hdr_off;

        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
    } else if (pkt.protocol == IPPROTO_UDP) {
        if (!skb_revalidate_data(skb, &head, &tail, l4_hdr_off + sizeof(struct udphdr))) {
            return TC_ACT_UNSPEC;
        }

        struct udphdr *udp = (void *)head + l4_hdr_off;

        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
    } else {
        //todo: support other transport protocols?
        return TC_ACT_UNSPEC;
    }

    connect_id.protocol = pkt.protocol;
    connect_id.address = pkt.src_addr;
    connect_id.port = pkt.src_port;
    net_ctx_t *net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
    if (net_ctx == NULL) {
        // We could have used traffic direction (ingress bool) to know if we
        // should look for src or dst, however, if we attach to a bridge
        // interface, src and dst are switched. For this reason, we look in the
        // network map for both src and dst
        connect_id.address = pkt.dst_addr;
        connect_id.port = pkt.dst_port;
        net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
        if (net_ctx == NULL) {
            // Check if network_map has an ip of 0.0.0.0. Note: A conflict
            // might occur between processes in different namespace that bind
            // to 0.0.0.0
            // TODO: handle network namespaces conflicts
            __builtin_memset(connect_id.address.s6_addr, 0, sizeof(connect_id.address.s6_addr));
            eth = (void *)head;
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

    // The tc perf_event_output handler will use the upper 32 bits of the flags
    // argument as a number of bytes to include of the packet payload in the
    // event data. If the size is too big, the call to bpf_perf_event_output
    // will fail and return -EFAULT.
    //
    // See bpf_skb_event_output in net/core/filter.c.
    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64)skb->len << 32;
    if (get_config(CONFIG_DEBUG_NET)){
        pkt.src_port = __bpf_ntohs(pkt.src_port);
        pkt.dst_port = __bpf_ntohs(pkt.dst_port);
        bpf_perf_event_output(skb, &net_events, flags, &pkt, sizeof(pkt));
    }
    else {
        // If not debugging, only send the minimal required data to save the
        // packet. This will be the timestamp (u64), net event_id (u32),
        // host_tid (u32), comm (16 bytes), packet len (u32), and ifindex (u32)
        bpf_perf_event_output(skb, &net_events, flags, &pkt, 40);
    }

    return TC_ACT_UNSPEC;
}

SEC("classifier")
int tc_egress(struct __sk_buff *skb) {
    return tc_probe(skb, false);
}

SEC("classifier")
int tc_ingress(struct __sk_buff *skb) {
    return tc_probe(skb, true);
}

char LICENSE[] SEC("license") = "GPL";
#ifndef CORE
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
#endif
