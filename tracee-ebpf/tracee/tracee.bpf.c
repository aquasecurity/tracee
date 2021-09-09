
// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

/* 
Note: This file is licenced differently from the rest of the project
SPDX-License-Identifier: GPL-2.0
Copyright (C) Aqua Security inc.
*/

#ifndef CORE
/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 * Note: types.h should be included before defining asm_inline or compilation might break
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
#define KBUILD_MODNAME "tracee"
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
#include "co_re_missing_definitions.h"
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

#ifdef CORE
#define get_kconfig(x) get_kconfig_val(x)
#else
#define get_kconfig(x) CONFIG_##x
#endif

// All kconfig variables used in this file should be placed here.
// Note:  Do not use CONFIG_ prefix. Sync with libbpfgo kernel_config.
// This allows libbpf to work without the system kconfig file.
#define ARCH_HAS_SYSCALL_WRAPPER 1000u

#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096          // Choosing this value to be the same as PATH_MAX
#define MAX_BYTES_ARR_SIZE  4096          // Max size of bytes array, arbitrarily chosen
#define MAX_STACK_ADDRESSES 1024          // Max amount of different stack trace addresses to buffer in the Map
#define MAX_STACK_DEPTH     20            // Max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE 16            // Max string filter size should be bounded to the size of the compared values (comm, uts)
#define FILE_MAGIC_HDR_SIZE 32            // Number of bytes to save from a file's header (for magic_write event)
#define FILE_MAGIC_MASK     31            // Mask used to pass verifier when submitting magic_write event bytes

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
#define U16_T         15UL
#define CRED_T        16UL
#define INT_ARR_2_T   17UL
#define TYPE_MAX      255UL

#define TAG_NONE           0UL

#if defined(bpf_target_x86)
#define SYS_OPEN              2
#define SYS_MMAP              9
#define SYS_MPROTECT          10
#define SYS_RT_SIGRETURN      15
#define SYS_EXECVE            59
#define SYS_EXIT              60
#define SYS_EXIT_GROUP        231
#define SYS_OPENAT            257
#define SYS_EXECVEAT          322
#define SYSCALL_CONNECT       42
#define SYSCALL_ACCEPT        43
#define SYSCALL_ACCEPT4       288
#define SYSCALL_LISTEN        50
#define SYSCALL_BIND          49
#elif defined(bpf_target_arm64)
#define SYS_OPEN              1000 // undefined in arm64
#define SYS_MMAP              222
#define SYS_MPROTECT          226
#define SYS_RT_SIGRETURN      139
#define SYS_EXECVE            221
#define SYS_EXIT              93
#define SYS_EXIT_GROUP        94
#define SYS_OPENAT            56
#define SYS_EXECVEAT          281
#define SYSCALL_CONNECT       203
#define SYSCALL_ACCEPT        202
#define SYSCALL_ACCEPT4       242
#define SYSCALL_LISTEN        201
#define SYSCALL_BIND          200
#endif

#define RAW_SYS_ENTER               1000
#define RAW_SYS_EXIT                1001
#define SCHED_PROCESS_FORK          1002
#define SCHED_PROCESS_EXEC          1003
#define SCHED_PROCESS_EXIT          1004
#define SCHED_SWITCH                1005
#define DO_EXIT                     1006
#define CAP_CAPABLE                 1007
#define VFS_WRITE                   1008
#define VFS_WRITEV                  1009
#define MEM_PROT_ALERT              1010
#define COMMIT_CREDS                1011
#define SWITCH_TASK_NS              1012
#define MAGIC_WRITE                 1013
#define CGROUP_ATTACH_TASK          1014
#define SECURITY_BPRM_CHECK         1015
#define SECURITY_FILE_OPEN          1016
#define SECURITY_INODE_UNLINK       1017
#define SECURITY_SOCKET_CREATE      1018
#define SECURITY_SOCKET_LISTEN      1019
#define SECURITY_SOCKET_CONNECT     1020
#define SECURITY_SOCKET_ACCEPT      1021
#define SECURITY_SOCKET_BIND        1022
#define SECURITY_SB_MOUNT           1023
#define SECURITY_BPF                1024
#define SECURITY_BPF_MAP            1025
#define SECURITY_KERNEL_READ_FILE   1026
#define SECURITY_INODE_MKNOD        1027
#define MAX_EVENT_ID                1028

#define NET_PACKET                      0
#define DEBUG_NET_SECURITY_BIND         1
#define DEBUG_NET_UDP_SENDMSG           2
#define DEBUG_NET_UDP_DISCONNECT        3
#define DEBUG_NET_UDP_DESTROY_SOCK      4
#define DEBUG_NET_UDPV6_DESTROY_SOCK    5
#define DEBUG_NET_INET_SOCK_SET_STATE   6
#define DEBUG_NET_TCP_CONNECT           7

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
#define CONFIG_DEBUG_NET            17
#define CONFIG_PROC_TREE_FILTER     18

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

#define CONT_ID_LEN 12

#ifndef CORE
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
// Use lower values on older kernels, where the instruction limit is 4096
#define MAX_STR_ARR_ELEM      40
#define MAX_ARGS_STR_ARR_ELEM 15
#define MAX_PATH_PREF_SIZE    64
#define MAX_PATH_COMPONENTS   20
#define MAX_BIN_CHUNKS        110
#else
// Otherwise, the sky is the limit (complexity limit of 1 million verified instructions)
#define MAX_STR_ARR_ELEM      128
#define MAX_ARGS_STR_ARR_ELEM 128
#define MAX_PATH_PREF_SIZE    128
#define MAX_PATH_COMPONENTS   48
#define MAX_BIN_CHUNKS        256
#endif
#else
// XXX: In the future, these values will be global volatile constants that 
//      can be set at runtime from userspace go code. This way we can dynamically
//      set them based on kernel version. libbpfgo needs this feature first.
//      For now setting the lower limit is the safest option.
#define MAX_STR_ARR_ELEM      40
#define MAX_ARGS_STR_ARR_ELEM 15
#define MAX_PATH_PREF_SIZE    64
#define MAX_PATH_COMPONENTS   20
#define MAX_BIN_CHUNKS        110
#endif

#ifndef CORE
#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })
#else
// Try using READ_KERN here, just don't embed them in each other
#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_core_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })
#endif

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = _type, \
  .key_size = sizeof(_key_type), \
  .value_size = sizeof(_value_type), \
  .max_entries = _max_entries, \
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

typedef struct event_context {
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
    char cont_id[16];           // Container ID, padding to 16 to keep the context struct aligned
    u32 eventid;
    s64 retval;
    u32 stack_id;
    u8 argnum;
} context_t;

typedef struct args {
    unsigned long args[7]; // the last element of this array is used to save the function entry timestamp
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

typedef struct container_id {
    char id[CONT_ID_LEN+1];
} container_id_t;

typedef struct alert {
    u64 ts;     // Timestamp
    u32 msg;    // Encoded message
    u8 payload; // Non zero if payload is sent to userspace
} alert_t;

// For a good summary about capabilities, see https://lwn.net/Articles/636533/
typedef struct slim_cred {
    uid_t  uid;             /* real UID of the task */
    gid_t  gid;             /* real GID of the task */
    uid_t  suid;            /* saved UID of the task */
    gid_t  sgid;            /* saved GID of the task */
    uid_t  euid;            /* effective UID of the task */
    gid_t  egid;            /* effective GID of the task */
    uid_t  fsuid;           /* UID for VFS ops */
    gid_t  fsgid;           /* GID for VFS ops */
    u64    cap_inheritable; /* caps our children can inherit */
    u64    cap_permitted;   /* caps we're permitted */
    u64    cap_effective;   /* caps we can actually use */
    u64    cap_bset;        /* capability bounding set */
    u64    cap_ambient;     /* Ambient capability set */
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

/*================================ KERNEL STRUCTS =============================*/

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
/*=================================== MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                         // Various configurations
BPF_HASH(kconfig_map, u32, u32);                        // Kernel config variables
BPF_HASH(chosen_events_map, u32, u32);                  // Events chosen by the user
BPF_HASH(traced_pids_map, u32, u32);                    // Keep track of traced pids
BPF_HASH(new_pids_map, u32, u32);                       // Keep track of the processes of newly executed binaries
BPF_HASH(new_pidns_map, u32, u32);                      // Keep track of new pid namespaces
BPF_HASH(pid_to_cont_id_map, u32, container_id_t);      // Map pid to container id
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
BPF_HASH(sockfd_map, u32, u32);                         // Persist sockfd from syscalls to be used in the corresponding lsm hooks
BPF_HASH(process_tree_map, u32, u32);                   // Used to filter events by the ancestry of the traced process
BPF_LRU_HASH(sock_ctx_map, u64, net_ctx_ext_t);         // Socket address to process context
BPF_LRU_HASH(network_map, local_net_id_t, net_ctx_t);   // Network identifier to process context
BPF_ARRAY(file_filter, path_filter_t, 3);               // Used to filter vfs_write events
BPF_ARRAY(string_store, path_filter_t, 1);              // Store strings from userspace
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);             // Percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // Holds offsets to bufs respectively
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);              // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);          // Used to store programs for tail calls
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);           // Used to store programs for tail calls
BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);  // Used to store stack traces

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                                // Events submission
BPF_PERF_OUTPUT(file_writes);                           // File writes events submission
BPF_PERF_OUTPUT(net_events);                            // Network events submission

/*================== KERNEL VERSION DEPENDANT HELPER FUNCTIONS =================*/

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
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(task->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards, and CO:RE:
    struct pid *tpid = READ_KERN(task->thread_pid);
    return READ_KERN(tpid->numbers[level].nr);
#endif
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(group_leader->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards, and CO:RE:
    struct pid *tpid = READ_KERN(group_leader->thread_pid);
    return READ_KERN(tpid->numbers[level].nr);
#endif
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    struct nsproxy *namespaceproxy = READ_KERN(real_parent->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0)) && !defined(CORE)
    // kernel 4.14-4.18:
    return READ_KERN(READ_KERN(real_parent->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards, and CO:RE:
    struct pid *tpid = READ_KERN(real_parent->thread_pid);
    return READ_KERN(tpid->numbers[level].nr);
#endif
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
    return READ_KERN(parent->pid);
}

static __always_inline u32 get_task_host_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

static __always_inline u32 get_task_host_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

static __always_inline int get_task_parent_flags(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->flags);
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    /* kernel 4.18-5.5:

    this is a workaround for reading sk_protocol bit-field, because bpf_probe_read doesn't really support reading
    this type of fields. so we use the sk_gso_max_segs field and go 24 bits backwards (i.e. 3 bytes) because
    sk_type is 16 bits, and sk_protocol is 8 bits (i.e. 1 byte).

    note: we define protocol as u16 so it'll be compatible with newer kernels.
    */

    u16 protocol = 0;
    bpf_probe_read(&protocol, 1, (void *)(&sock->sk_gso_max_segs) - 3);

    return protocol;
#else
    // kernel 5.6 onwards:
    return READ_KERN(sock->sk_protocol);
#endif
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
    container_id_t *container_id = bpf_map_lookup_elem(&pid_to_cont_id_map, &context->host_tid);
    if (container_id != NULL) {
        __builtin_memcpy(context->cont_id, container_id->id, CONT_ID_LEN);
    }
    context->ts = bpf_ktime_get_ns();

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

static __always_inline int get_kconfig_val(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&kconfig_map, &key);

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

    if (!equality_filter_matches(CONFIG_PROC_TREE_FILTER, &process_tree_map, &context.pid))
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

    // Data saved to submit buf: [type][tag][ ... buffer[size] ... ]

    if ((type == 0) || (size == 0))
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // If we don't have enough space - return
    if (*off > MAX_PERCPU_BUFSIZE - (size+2))
        return 0;

    // Save argument type & tag
    submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)] = type;
    submit_p->buf[(*off+1) & (MAX_PERCPU_BUFSIZE-1)] = tag;

    // Satisfy validator for probe read
    if ((*off+2) <= MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Read into buffer
        if (bpf_probe_read(&(submit_p->buf[*off+2]), size, ptr) == 0) {
            // We update buf_off only if all writes were successful
            *off += size+2;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_bytes_to_buf(buf_t *submit_p, void *ptr, u32 size, u8 tag)
{
    // Data saved to submit buf: [type][tag][size][ ... bytes ... ]

    if (size == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // If we don't have enough space - return
    if (*off > MAX_PERCPU_BUFSIZE - (size+2+sizeof(int)))
        return 0;

    // Save argument type & tag
    submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)] = BYTES_T;
    submit_p->buf[(*off+1) & (MAX_PERCPU_BUFSIZE-1)] = tag;

    if ((*off+2) <= MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE - sizeof(int)) {
        // Save size to buffer
        if (bpf_probe_read(&(submit_p->buf[*off+2]), sizeof(int), &size) != 0) {
            return 0;
        }
    }

    if ((*off+2+sizeof(int)) <= MAX_PERCPU_BUFSIZE - MAX_BYTES_ARR_SIZE) {
        // Read bytes into buffer
        if (bpf_probe_read(&(submit_p->buf[*off+2+sizeof(int)]), size & (MAX_BYTES_ARR_SIZE-1), ptr) == 0) {
            // We update buf_off only if all writes were successful
            *off += size+2+sizeof(int);
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_str_to_buf(buf_t *submit_p, void *ptr, u8 tag)
{
    // Data saved to submit buf: [type][tag][size][ ... string ... ]

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // If we don't have enough space - return
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0;

    // Save argument type & tag
    submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)] = STR_T;
    submit_p->buf[(*off+1) & (MAX_PERCPU_BUFSIZE-1)] = tag;

    // Satisfy validator for probe read
    if ((*off+2) <= MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Read into buffer
        int sz = bpf_probe_read_str(&(submit_p->buf[*off+2+sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
            // Satisfy validator for probe read
            if ((*off+2) > MAX_PERCPU_BUFSIZE - sizeof(int)) {
                return 0;
            }
            __builtin_memcpy(&(submit_p->buf[*off+2]), &sz, sizeof(int));
            *off += sz + sizeof(int) + 2;
            return 1;
        }
    }

    return 0;
}

static __always_inline int save_str_arr_to_buf(buf_t *submit_p, const char __user *const __user *ptr, u8 tag)
{
    // Data saved to submit buf: [type][tag][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // Save argument type & tag
    submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)] = STR_ARR_T;
    submit_p->buf[(*off+1) & (MAX_PERCPU_BUFSIZE-1)] = tag;

    // Save space for number of elements (1 byte)
    u32 orig_off = *off+2;
    *off += 3;

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
                // Satisfy validator
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
            // Satisfy validator
            goto out;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)] = elem_num;
    return 1;
}

// This helper saves null (0x00) delimited string array into buf
static __always_inline int save_args_str_arr_to_buf(buf_t *submit_p, const char *start, const char *end, int elem_num, u8 tag)
{
    // Data saved to submit buf: [type][tag][string count][str1 size][str1][str2 size][str2]...

    u8 count=0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // Save argument type & tag
    submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)] = STR_ARR_T;
    submit_p->buf[(*off+1) & (MAX_PERCPU_BUFSIZE-1)] = tag;

    // Save space for number of elements (1 byte)
    u32 orig_off = *off+2;
    *off += 3;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS_STR_ARR_ELEM; i++) {
        if (elem_num <= 0 || start >= end)
            goto out;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int) & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), MAX_STRING_SIZE, start);
        if (sz > 0) {
            if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
            *off += sz + sizeof(int);
            elem_num--;
            count++;
            start += sz;
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
            // Satisfy validator
            goto out;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        elem_num--;
        count++;
    }
out:
    // save number of elements in the array
    submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)] = count;
    return 1;
}

static __always_inline int save_path_to_str_buf(buf_t *string_p, const struct path *path)
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
    return buf_off;
}

static __always_inline int save_dentry_path_to_str_buf(buf_t *string_p, struct dentry* dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

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
    args->args[6] = saved_args->args[6];

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

static __always_inline int save_sockfd(u32 sockfd)
{
    u32 pid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&sockfd_map, &pid, &sockfd, BPF_ANY);

    return 0;
}

static __always_inline int load_sockfd(u32 *sockfd)
{
    u32 pid = bpf_get_current_pid_tgid();

    u32 *saved_sockfd = bpf_map_lookup_elem(&sockfd_map, &pid);
    if (saved_sockfd == 0) {
        // missed entry or not traced
        return -1;
    }

    *sockfd = *saved_sockfd;
    bpf_map_delete_elem(&sockfd_map, &pid);

    return 0;
}

static __always_inline int del_sockfd()
{
    u32 pid = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&sockfd_map, &pid);

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
            case INT_ARR_2_T:
                size = sizeof(int[2]);
                rc = save_to_submit_buf(submit_p, (void*)(args->args[i]), size, type, tag);
                break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T) && (type != INT_ARR_2_T)) {
            rc = save_to_submit_buf(submit_p, (void*)&(args->args[i]), size, type, tag);
        }

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
    // resave the context to update timestamp
    context_t context = init_and_save_context(ctx, submit_p, id, argnum, ret);
    context.ts = args->args[6];
    save_context_to_buf(submit_p, (void*)&context);

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

    /*
    this function is inspired by the 'inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)' function.
    reference: 'https://elixir.bootlin.com/linux/latest/source/net/ipv6/af_inet6.c#L509'.
    */

    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);

    struct in6_addr addr = {};
    addr = get_sock_v6_rcv_saddr(sk);
    if (ipv6_addr_any(&addr)){
        addr = get_ipv6_pinfo_saddr(np);
    }

    /*
    the flowinfo field can be specified by the user to indicate a network flow. how it is used by the kernel, or
    whether it is enforced to be unique is not so obvious.
    getting this value is only supported by the kernel for outgoing packets using the 'struct ipv6_pinfo'.
    in any case, leaving it with value of 0 won't affect our representation of network flows.
    */
    net_details->flowinfo = 0;
    /*
    the scope_id field can be specified by the user to indicate the network interface from which to send a packet. this
    only applies for link-local addresses, and is used only by the local kernel.
    getting this value is done by using the 'ipv6_iface_scope_id(const struct in6_addr *addr, int iface)' function.
    in any case, leaving it with value of 0 won't affect our representation of network flows.
    */
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

/*============================== SYSCALL HOOKS ==============================*/

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long id)
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    args_t args_tmp = {};
    int id = ctx->args[1];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)) {
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
#if defined(bpf_target_x86)
        // In x86-64, r10 is used instead of rcx to pass the fourth parameter of a syscall
        // see also: https://stackoverflow.com/questions/21322100/linux-x64-why-does-r10-come-before-r8-and-r9-in-syscalls
        args_tmp.args[3] = regs.r10;
#else
        args_tmp.args[3] = PT_REGS_PARM4(&regs);
#endif
        args_tmp.args[4] = PT_REGS_PARM5(&regs);
        args_tmp.args[5] = PT_REGS_PARM6(&regs);
    }
} else {
    bpf_probe_read(args_tmp.args, sizeof(6 * sizeof(u64)), (void *)ctx->args);
}

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
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
    else if (id == SYSCALL_CONNECT || id == SYSCALL_ACCEPT || id == SYSCALL_ACCEPT4 || id == SYSCALL_BIND || id == SYSCALL_LISTEN) {
        u32 sockfd = args_tmp.args[0];
        save_sockfd(sockfd);
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
        // save the timestamp at function entry
        args_tmp.args[6] = bpf_ktime_get_ns();
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
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
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

    if (id == SYSCALL_CONNECT || id == SYSCALL_ACCEPT || id == SYSCALL_ACCEPT4 || id == SYSCALL_BIND || id == SYSCALL_LISTEN) {
        del_sockfd();
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

// include/trace/events/sched.h:
// TP_PROTO(struct task_struct *parent, struct task_struct *child)
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // Note: we don't place should_trace() here, so we can keep track of the cgroups in the system
    struct task_struct *parent = (struct task_struct*)ctx->args[0];
    struct task_struct *child = (struct task_struct*)ctx->args[1];

    int parent_pid = get_task_host_pid(parent);
    int child_pid = get_task_host_pid(child);

    int parent_tgid = get_task_host_tgid(parent);
    int child_tgid = get_task_host_tgid(child);

    container_id_t *container_id = bpf_map_lookup_elem(&pid_to_cont_id_map, &parent_pid);
    if (container_id != NULL) {
        // copy the container id of the parent process to the child process
        bpf_map_update_elem(&pid_to_cont_id_map, &child_pid, &container_id->id, BPF_ANY);
    }

    // update process tree map if the parent has an entry
    u32 *tgid_filtered = bpf_map_lookup_elem(&process_tree_map, &parent_tgid);
    if (tgid_filtered) {
        bpf_map_update_elem(&process_tree_map, &child_tgid, tgid_filtered, BPF_ANY);
    } 

    if (!should_trace())
        return 0;

    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    bpf_map_update_elem(&traced_pids_map, &child_pid, &child_pid, BPF_ANY);
    if (get_config(CONFIG_NEW_PID_FILTER)) {
        bpf_map_update_elem(&new_pids_map, &child_pid, &child_pid, BPF_ANY);
    }

    if (event_chosen(SCHED_PROCESS_FORK)) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, SCHED_PROCESS_FORK, 4 /*argnum*/, 0 /*ret*/);
        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        int parent_ns_pid = get_task_ns_pid(parent);
        int child_ns_pid = get_task_ns_pid(child);

        save_to_submit_buf(submit_p, (void*)&parent_pid, sizeof(int), INT_T, DEC_ARG(0, *tags));
        save_to_submit_buf(submit_p, (void*)&parent_ns_pid, sizeof(int), INT_T, DEC_ARG(1, *tags));
        save_to_submit_buf(submit_p, (void*)&child_pid, sizeof(int), INT_T, DEC_ARG(2, *tags));
        save_to_submit_buf(submit_p, (void*)&child_ns_pid, sizeof(int), INT_T, DEC_ARG(3, *tags));

        events_perf_submit(ctx);
    }

    return 0;
}

// include/trace/events/sched.h:
//TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SCHED_PROCESS_EXEC, 6, 0);

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

    unsigned long arg_start = 0, arg_end = 0;
    int argc = 0;

    // bprm->mm is null at this point (set by begin_new_exec()), and task->mm is already initialized
    struct mm_struct *mm = get_mm_from_task(task);

    arg_start = get_arg_start_from_mm(mm);
    arg_end = get_arg_end_from_mm(mm);
    argc = get_argc_from_bprm(bprm);

    // Instruction limit exceeds when adding env vars in kernels < 5.2
    //unsigned long env_start, env_end;
    //env_start = get_env_start_from_mm(mm);
    //env_end = get_env_end_from_mm(mm);
    //int envc = get_envc_from_bprm(bprm);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_path_to_str_buf(string_p, &file->f_path);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    // Note: Starting from kernel 5.9, there are two new interesting fields in bprm that we should consider adding:
    // 1. struct file *executable - which can be used to get the executable name passed to an interpreter
    // 2. fdpath - generated filename for execveat (after resolving dirfd)

    save_str_to_buf(submit_p, (void *)filename, DEC_ARG(0, *tags));
    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(1, *tags));
    save_args_str_arr_to_buf(submit_p, (void *)arg_start, (void *)arg_end, argc, DEC_ARG(2, *tags));
    //save_args_str_arr_to_buf(submit_p, (void *)env_start, (void *)env_end, envc, DEC_ARG(3, *tags));
    save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(4, *tags));
    save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(5, *tags));
    save_to_submit_buf(submit_p, &invoked_from_kernel, sizeof(int), INT_T, DEC_ARG(6, *tags));

    events_perf_submit(ctx);
    return 0;
}

// include/trace/events/sched.h:
// TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u32 tgid = id >> 32;

    if (!should_trace()) {
        // Note: we need to remove the container id here as we always add it to the map in cgroup_attach_task event.
        bpf_map_delete_elem(&pid_to_cont_id_map, &pid);
        bpf_map_delete_elem(&process_tree_map, &tgid);
        return 0;
    }
    bpf_map_delete_elem(&process_tree_map, &tgid);

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    init_and_save_context(ctx, submit_p, SCHED_PROCESS_EXIT, 0, 0);

    // Remove the container id (if any) from pid_to_cont_id_map
    bpf_map_delete_elem(&pid_to_cont_id_map, &pid);

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

    events_perf_submit(ctx);
    return 0;
}

// include/trace/events/sched.h:
// TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next),
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    if (!should_trace())
        return 0;

    if (!event_chosen(SCHED_SWITCH))
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SCHED_SWITCH, 5 /*argnum*/, 0 /*ret*/);
    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    struct task_struct *prev = (struct task_struct*)ctx->args[1];
    struct task_struct *next = (struct task_struct*)ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(submit_p, (void*)&cpu, sizeof(int), INT_T, DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, (void*)&prev_pid, sizeof(int), INT_T, DEC_ARG(1, *tags));
    save_str_to_buf(submit_p, prev->comm, DEC_ARG(2, *tags));
    save_to_submit_buf(submit_p, (void*)&next_pid, sizeof(int), INT_T, DEC_ARG(3, *tags));
    save_str_to_buf(submit_p, next->comm, DEC_ARG(4, *tags));

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

// include/trace/events/sched.h:
// TP_PROTO(struct cgroup *dst_cgrp, const char *path, struct task_struct *task, bool threadgroup)
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    // Note: we don't place should_trace() here, so we can keep track of the cgroups in the system
    container_id_t container_id = {0};
    struct cgroup *dst_cgrp = (struct cgroup*)ctx->args[0];
    struct task_struct *task = (struct task_struct*)ctx->args[2];
    const char *cgrp_dirname = get_cgroup_dirname(dst_cgrp);

    bpf_probe_read_str(&container_id.id, CONT_ID_LEN+1, cgrp_dirname);

    if (has_prefix("docker-", (char*)&container_id.id, 8))
        bpf_probe_read_str(&container_id.id, CONT_ID_LEN+1, cgrp_dirname+7);

    // Only update pid_to_cont_id_map for this pid if no element already exists.
    // this way, we only keep track of the first level in the cgroup hierarchy
    int pid = get_task_host_pid(task);
    bpf_map_update_elem(&pid_to_cont_id_map, &pid, &container_id.id, BPF_NOEXIST);

    if (event_chosen(CGROUP_ATTACH_TASK) && should_trace()) {
        buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

        context_t context = init_and_save_context(ctx, submit_p, CGROUP_ATTACH_TASK, 1 /*argnum*/, 0 /*ret*/);

        u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }

        save_str_to_buf(submit_p, (void *)ctx->args[1], DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }

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
    save_path_to_str_buf(string_p, &file->f_path);
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

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_path_to_str_buf(string_p, &file->f_path);
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
    if (get_config(CONFIG_SHOW_SYSCALL)) {
        int syscall_nr = get_syscall_ev_id_from_regs();
        if (syscall_nr >= 0) {
            context.argnum++;
            save_context_to_buf(submit_p, (void*)&context);
            save_to_submit_buf(submit_p, (void*)&syscall_nr, sizeof(int), INT_T, DEC_ARG(4, *tags));
        }
    }

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_security_sb_mount)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_SB_MOUNT, 4 /*argnum*/, 0 /*ret*/);

    const char *dev_name = (const char *)PT_REGS_PARM1(ctx);
    const struct path *path = (const struct path *)PT_REGS_PARM2(ctx);
    const char *type = (const char *)PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long)PT_REGS_PARM4(ctx);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    save_path_to_str_buf(string_p, path);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL)
        return -1;

    context.argnum = save_str_to_buf(submit_p, (void *)dev_name, DEC_ARG(0, *tags));
    context.argnum += save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(1, *tags));
    context.argnum += save_str_to_buf(submit_p, (void *)type, DEC_ARG(2, *tags));
    context.argnum += save_to_submit_buf(submit_p, &flags, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));

    save_context_to_buf(submit_p, (void*)&context);

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

    context_t context = init_and_save_context(ctx, submit_p, COMMIT_CREDS, 2 /*argnum*/, 0 /*ret*/);

    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *old = (struct cred *)READ_KERN(task->real_cred);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    old_slim.uid = READ_KERN(old->uid.val);
    old_slim.gid = READ_KERN(old->gid.val);
    old_slim.suid = READ_KERN(old->suid.val);
    old_slim.sgid = READ_KERN(old->sgid.val);
    old_slim.euid = READ_KERN(old->euid.val);
    old_slim.egid = READ_KERN(old->egid.val);
    old_slim.fsuid = READ_KERN(old->fsuid.val);
    old_slim.fsgid = READ_KERN(old->fsgid.val);

    new_slim.uid = READ_KERN(new->uid.val);
    new_slim.gid = READ_KERN(new->gid.val);
    new_slim.suid = READ_KERN(new->suid.val);
    new_slim.sgid = READ_KERN(new->sgid.val);
    new_slim.euid = READ_KERN(new->euid.val);
    new_slim.egid = READ_KERN(new->egid.val);
    new_slim.fsuid = READ_KERN(new->fsuid.val);
    new_slim.fsgid = READ_KERN(new->fsgid.val);

    // Currently, (2021), there are ~40 capabilities in the Linux kernel which are stored in an u32 array of length 2.
    // This might change in the (not so near) future as more capabilities will be added.
    // For now, we use u64 to store this array in one piece
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

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void*)&old_slim, sizeof(slim_cred_t), CRED_T, DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, (void*)&new_slim, sizeof(slim_cred_t), CRED_T, DEC_ARG(1, *tags));


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
            int syscall_nr = get_syscall_ev_id_from_regs();
            if (syscall_nr >= 0) {
                context.argnum++;
                save_context_to_buf(submit_p, (void*)&context);
                save_to_submit_buf(submit_p, (void*)&syscall_nr, sizeof(int), INT_T, DEC_ARG(2, *tags));
            }
        }

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
}

SEC("kprobe/security_socket_create")
int BPF_KPROBE(trace_security_socket_create)
{
    // trace the event security_socket_create

    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_SOCKET_CREATE, 4 /*argnum*/, 0 /*ret*/);

    // getting event tags
    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    int family = (int)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM2(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);
    int kern = (int)PT_REGS_PARM4(ctx);

    save_to_submit_buf(submit_p, (void *)&family, sizeof(int), INT_T, DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, (void *)&type, sizeof(int), INT_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, (void *)&protocol, sizeof(int), INT_T, DEC_ARG(2, *tags));
    save_to_submit_buf(submit_p, (void *)&kern, sizeof(int), INT_T, DEC_ARG(3, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    int backlog = (int)PT_REGS_PARM2(ctx);

    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ( (family != AF_INET) && (family != AF_INET6) ) {
        return 0;
    }

    u32 sockfd = -1;
    load_sockfd(&sockfd);

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_SOCKET_LISTEN, 3 /*argnum*/, 0 /*ret*/);

    // getting event tags
    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void *)&sockfd, sizeof(u32), INT_T, DEC_ARG(0, *tags));

    if ( family == AF_INET ){

        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);

        struct sockaddr_in local;
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(submit_p, (void *)&local, sizeof(struct sockaddr_in), SOCKADDR_T, DEC_ARG(1, *tags));

    }
    else if ( family == AF_INET6 ){

        net_conn_v6_t net_details = {};
        get_network_details_from_sock_v6(sk, &net_details, 0);

        struct sockaddr_in6 local;
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(submit_p, (void *)&local, sizeof(struct sockaddr_in6), SOCKADDR_T, DEC_ARG(1, *tags));
    }

    save_to_submit_buf(submit_p, (void *)&backlog, sizeof(int), INT_T, DEC_ARG(2, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ( (sa_fam != AF_INET) && (sa_fam != AF_INET6) ) {
        return 0;
    }

    u32 sockfd = -1;
    load_sockfd(&sockfd);

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_SOCKET_CONNECT, 2 /*argnum*/, 0 /*ret*/);

    // getting event tags
    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void *)&sockfd, sizeof(u32), INT_T, DEC_ARG(0, *tags));

    if (sa_fam == AF_INET) {
        // saving to submit buffer
        save_to_submit_buf(submit_p, (void *)address, sizeof(struct sockaddr_in), SOCKADDR_T, DEC_ARG(1, *tags));

    }
    else if (sa_fam == AF_INET6) {
        // saving to submit buffer
        save_to_submit_buf(submit_p, (void *)address, sizeof(struct sockaddr_in6), SOCKADDR_T, DEC_ARG(1, *tags));
    }

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ( (family != AF_INET) && (family != AF_INET6) ) {
        return 0;
    }

    u32 sockfd = -1;
    load_sockfd(&sockfd);

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_SOCKET_ACCEPT, 2 /*argnum*/, 0 /*ret*/);

    // getting event tags
    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void *)&sockfd, sizeof(u32), INT_T, DEC_ARG(0, *tags));

    if ( family == AF_INET ){

        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);

        struct sockaddr_in local;
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(submit_p, (void *)&local, sizeof(struct sockaddr_in), SOCKADDR_T, DEC_ARG(1, *tags));

    }
    else if ( family == AF_INET6 ){

        net_conn_v6_t net_details = {};
        get_network_details_from_sock_v6(sk, &net_details, 0);

        struct sockaddr_in6 local;
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(submit_p, (void *)&local, sizeof(struct sockaddr_in6), SOCKADDR_T, DEC_ARG(1, *tags));
    }

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ( (sa_fam != AF_INET) && (sa_fam != AF_INET6) ) {
        return 0;
    }

    u32 sockfd = -1;
    load_sockfd(&sockfd);

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_SOCKET_BIND, 2 /*argnum*/, 0 /*ret*/);

    // getting event tags
    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    save_to_submit_buf(submit_p, (void *)&sockfd, sizeof(u32), INT_T, DEC_ARG(0, *tags));

    u16 protocol = get_sock_protocol(sk);
    local_net_id_t connect_id = {0};
    connect_id.protocol = protocol;

    if (sa_fam == AF_INET) {

        save_to_submit_buf(submit_p, (void *)address, sizeof(struct sockaddr_in), SOCKADDR_T, DEC_ARG(1, *tags));

        struct sockaddr_in *addr = (struct sockaddr_in *)address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin_port)){
            connect_id.address.s6_addr32[3] = READ_KERN(addr->sin_addr).s_addr;
            connect_id.address.s6_addr16[5] = 0xffff;
            connect_id.port = READ_KERN(addr->sin_port);
        }
    }
    else if (sa_fam == AF_INET6) {

        save_to_submit_buf(submit_p, (void *)address, sizeof(struct sockaddr_in6), SOCKADDR_T, DEC_ARG(1, *tags));

        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin6_port)){
            connect_id.address = READ_KERN(addr->sin6_addr);
            connect_id.port = READ_KERN(addr->sin6_port);
        }
    }

    if (connect_id.port) {
        net_ctx_t net_ctx;
        net_ctx.host_tid = context.host_tid;
        __builtin_memcpy(net_ctx.comm, context.comm, TASK_COMM_LEN);
        bpf_map_update_elem(&network_map, &connect_id, &net_ctx, BPF_ANY);
    }

    events_perf_submit(ctx);

    // netDebug event
    if (get_config(CONFIG_DEBUG_NET)) {
        net_debug_t debug_event = {0};
        debug_event.ts = bpf_ktime_get_ns();
        debug_event.host_tid = context.host_tid;
        __builtin_memcpy(debug_event.comm, context.comm, TASK_COMM_LEN);
        debug_event.event_id = DEBUG_NET_SECURITY_BIND;
        debug_event.local_addr = connect_id.address;
        debug_event.local_port = __bpf_ntohs(connect_id.port);
        debug_event.protocol = protocol;
        bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, &debug_event, sizeof(debug_event));
    }

    return 0;
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
    if (!should_trace())
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u32 tid = bpf_get_current_pid_tgid();

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_SENDMSG, sk, tid);
}

SEC("kprobe/__udp_disconnect")
int BPF_KPROBE(trace_udp_disconnect)
{
    if (!should_trace())
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_DISCONNECT, sk, 0);
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(trace_udp_destroy_sock)
{
    if (!should_trace())
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_UDP_DESTROY_SOCK, sk, 0);
}

SEC("kprobe/udpv6_destroy_sock")
int BPF_KPROBE(trace_udpv6_destroy_sock)
{
    if (!should_trace())
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

    struct sock *sk = (struct sock *)ctx->args[0];
    int old_state = ctx->args[1];
    int new_state = ctx->args[2];

    // Sometimes the socket state may be changed by other contexts that handle the tcp network stack (e.g. network driver).
    // In these cases, we won't pass the should_trace() check.
    // To overcome this problem, we save the socket pointer in sock_ctx_map in states that we observed to have the correct context.
    // We can then check for the existence of a socket in the map, and continue if it was traced before.
    net_ctx_ext_t *sock_ctx_p = bpf_map_lookup_elem(&sock_ctx_map, &sk);
    if (!sock_ctx_p) {
        if (!should_trace()) {
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
                net_ctx_ext.host_tid = bpf_get_current_pid_tgid();
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
        // At this point, port equals 0, so we will not be able to use current connect_id as a key to network map
        // We used the value saved in sock_ctx_map instead
        if (sock_ctx_p) {
            connect_id.port = sock_ctx_p->local_port;
        }
        bpf_map_delete_elem(&sock_ctx_map, &sk);
        bpf_map_delete_elem(&network_map, &connect_id);
        break;
    }

    // netDebug event
    if (get_config(CONFIG_DEBUG_NET)) {
        debug_event.ts = bpf_ktime_get_ns();
        if (!sock_ctx_p) {
            debug_event.host_tid = bpf_get_current_pid_tgid();
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
    if (!should_trace())
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

    u32 tid = bpf_get_current_pid_tgid();

    net_ctx_ext.host_tid = tid;
    bpf_get_current_comm(&net_ctx_ext.comm, sizeof(net_ctx_ext.comm));
    net_ctx_ext.local_port = connect_id.port;
    bpf_map_update_elem(&sock_ctx_map, &sk, &net_ctx_ext, BPF_ANY);

    return net_map_update_or_delete_sock(ctx, DEBUG_NET_TCP_CONNECT, sk, tid);
}

SEC("kprobe/send_bin")
int BPF_KPROBE(send_bin)
{
    // Note: sending the data to the userspace have the following constraints:
    // 1. We need a buffer that we know it's exact size (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data can be overridden if userspace doesn't consume it fast enough

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
        bpf_tail_call(ctx, &prog_array, TAIL_SEND_BIN);
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
    save_path_to_str_buf(string_p, &file->f_path);
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
        context_t context = init_and_save_context(ctx, submit_p, MAGIC_WRITE, 4 /*argnum*/, PT_REGS_RC(ctx));

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
        save_to_submit_buf(submit_p, &s_dev, sizeof(dev_t), DEV_T_T, DEC_ARG(2, *tags));
        save_to_submit_buf(submit_p, &inode_nr, sizeof(unsigned long), ULONG_T, DEC_ARG(3, *tags));

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
    save_path_to_str_buf(string_p, &file->f_path);
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
    u32 pid = context.pid;

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

SEC("kprobe/security_bpf")
int BPF_KPROBE(trace_security_bpf)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_BPF, 1 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags)
        return -1;

    int cmd = (int)PT_REGS_PARM1(ctx);

    /* 1st argument == cmd (int) */
    save_to_submit_buf(submit_p, (void *)&cmd, sizeof(int), INT_T, DEC_ARG(0, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(trace_security_bpf_map)
{
    if (!should_trace())
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_BPF_MAP, 2 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags)
        return -1;

    struct bpf_map *map = (struct bpf_map *)PT_REGS_PARM1(ctx);

    /* 1st argument == map_id (u32) */
    save_to_submit_buf(submit_p, (void *)&map->id, sizeof(int), UINT_T, DEC_ARG(0, *tags));
    /* 2nd argument == map_name (const char *) */
    save_str_to_buf(submit_p, (void *)&map->name, DEC_ARG(1, *tags));

    events_perf_submit(ctx);
    return 0;
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    if (!should_trace()) {
        return 0;
    }

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL) {
        return 0;
    }

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_KERNEL_READ_FILE, 3 /*argnum*/, 0 /*ret*/);

    struct file* file = (struct file*)PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL) {
        return -1;
    }
    save_path_to_str_buf(string_p, &file->f_path);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL) {
        return -1;
    }

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

SEC("kprobe/security_inode_mknod")
int BPF_KPROBE(trace_security_inode_mknod)
{
    if (!should_trace()) {
        return 0;
    }

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL) {
        return 0;
    }

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = init_and_save_context(ctx, submit_p, SECURITY_INODE_MKNOD, 3 /*argnum*/, 0 /*ret*/);

    u64 *tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    struct dentry* dentry = (struct dentry*)PT_REGS_PARM2(ctx);
    unsigned short mode = (unsigned short)PT_REGS_PARM3(ctx);
    unsigned int dev = (unsigned int)PT_REGS_PARM4(ctx);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL) {
        return -1;
    }

    save_dentry_path_to_str_buf(string_p, dentry);
    u32 *off = get_buf_off(STRING_BUF_IDX);
    if (off == NULL) {
        return -1;
    }
    save_str_to_buf(submit_p, (void *)&string_p->buf[*off], DEC_ARG(0, *tags));
    save_to_submit_buf(submit_p, &mode, sizeof(unsigned short), U16_T, DEC_ARG(1, *tags));
    save_to_submit_buf(submit_p, &dev, sizeof(unsigned int), UINT_T, DEC_ARG(2, *tags));

    events_perf_submit(ctx);
    return 0;
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
        // We could have used traffic direction (ingress bool) to know if we should look for src or dst
        // however, if we attach to a bridge interface, src and dst are switched
        // For this reason, we look in the network map for both src and dst
        connect_id.address = pkt.dst_addr;
        connect_id.port = pkt.dst_port;
        net_ctx = bpf_map_lookup_elem(&network_map, &connect_id);
        if (net_ctx == NULL) {
            // Check if network_map has an ip of 0.0.0.0
            // Note: A conflict might occur between processes in different namespace that bind to 0.0.0.0
            // todo: handle network namespaces conflicts
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

    /* The tc perf_event_output handler will use the upper 32 bits
     * of the flags argument as a number of bytes to include of the
     * packet payload in the event data. If the size is too big, the
     * call to bpf_perf_event_output will fail and return -EFAULT.
     *
     * See bpf_skb_event_output in net/core/filter.c.
     *
     */
    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64)skb->len << 32;
    if (get_config(CONFIG_DEBUG_NET)){
        pkt.src_port = __bpf_ntohs(pkt.src_port);
        pkt.dst_port = __bpf_ntohs(pkt.dst_port);
        bpf_perf_event_output(skb, &net_events, flags, &pkt, sizeof(pkt));
    }
    else {
        // If not debugging, only send the minimal required data to save the packet.
        // This will be the timestamp (u64), net event_id (u32), host_tid (u32), comm (16 bytes), packet len (u32), and ifindex (u32)
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
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
