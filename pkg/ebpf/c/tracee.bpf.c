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

    #if defined(CONFIG_FUNCTION_TRACER)
        #define CC_USING_FENTRY
    #endif

    #include <linux/perf_event.h>
    #include <linux/kprobes.h>
    #include <linux/uprobes.h>
    #include <linux/trace_events.h>
    #include <linux/bpf_verifier.h>

    #include "missing_noncore_definitions.h"

#else
    // CO:RE is enabled
    #include <vmlinux.h>
    #include <missing_definitions.h>

#endif

#undef container_of
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";
#ifndef CORE
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
#endif

#if defined(bpf_target_x86)
    #define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
    #define PT_REGS_PARM6(x) ((x)->regs[5])
#endif

// INTERNAL ----------------------------------------------------------------------------------------

// clang-format off
#define MAX_PERCPU_BUFSIZE  (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096      // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE  4096      // max size of bytes array (arbitrarily chosen)
#define MAX_STACK_ADDRESSES 1024      // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH     20        // max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE 16        // bounded to size of the compared values (comm)
#define MAX_BIN_PATH_SIZE   256       // max binary path size
#define FILE_MAGIC_HDR_SIZE 32        // magic_write: bytes to save from a file's header
#define FILE_MAGIC_MASK     31        // magic_write: mask used for verifier boundaries
#define NET_SEQ_OPS_SIZE    4         // print_net_seq_ops: struct size - TODO: replace with uprobe argument
#define NET_SEQ_OPS_TYPES   6         // print_net_seq_ops: argument size - TODO: replace with uprobe argument
#define MAX_KSYM_NAME_SIZE  64
#define UPROBE_MAGIC_NUMBER 20220829
#define ARGS_BUF_SIZE       32000
#define MAX_MEM_DUMP_SIZE   127
// clang-format on

// helper macros for branch prediction
#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

enum buf_idx_e
{
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
    TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT,
    TAIL_VFS_READ,
    TAIL_VFS_READV,
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
    U8_T,
    TYPE_MAX = 255UL
};

#define UNDEFINED_SYSCALL 1000

#if defined(bpf_target_x86)
    #define SYSCALL_READ                   0
    #define SYSCALL_WRITE                  1
    #define SYSCALL_OPEN                   2
    #define SYSCALL_CLOSE                  3
    #define SYSCALL_FSTAT                  5
    #define SYSCALL_LSEEK                  8
    #define SYSCALL_MMAP                   9
    #define SYSCALL_MPROTECT               10
    #define SYSCALL_RT_SIGRETURN           15
    #define SYSCALL_IOCTL                  16
    #define SYSCALL_PREAD64                17
    #define SYSCALL_PWRITE64               18
    #define SYSCALL_READV                  19
    #define SYSCALL_WRITEV                 20
    #define SYSCALL_DUP                    32
    #define SYSCALL_DUP2                   33
    #define SYSCALL_SOCKET                 41
    #define SYSCALL_CONNECT                42
    #define SYSCALL_ACCEPT                 43
    #define SYSCALL_SENDTO                 44
    #define SYSCALL_RECVFROM               45
    #define SYSCALL_SENDMSG                46
    #define SYSCALL_RECVMSG                47
    #define SYSCALL_SHUTDOWN               48
    #define SYSCALL_BIND                   49
    #define SYSCALL_LISTEN                 50
    #define SYSCALL_GETSOCKNAME            51
    #define SYSCALL_GETPEERNAME            52
    #define SYSCALL_SETSOCKOPT             54
    #define SYSCALL_GETSOCKOPT             55
    #define SYSCALL_EXECVE                 59
    #define SYSCALL_EXIT                   60
    #define SYSCALL_FCNTL                  72
    #define SYSCALL_FLOCK                  73
    #define SYSCALL_FSYNC                  74
    #define SYSCALL_FDATASYNC              75
    #define SYSCALL_FTRUNCATE              77
    #define SYSCALL_GETDENTS               78
    #define SYSCALL_FCHDIR                 81
    #define SYSCALL_FCHMOD                 91
    #define SYSCALL_FCHOWN                 93
    #define SYSCALL_FSTATFS                138
    #define SYSCALL_READAHEAD              187
    #define SYSCALL_FSETXATTR              190
    #define SYSCALL_FGETXATTR              193
    #define SYSCALL_FLISTXATTR             196
    #define SYSCALL_FREMOVEXATTR           199
    #define SYSCALL_GETDENTS64             217
    #define SYSCALL_FADVISE64              221
    #define SYSCALL_EXIT_GROUP             231
    #define SYSCALL_EPOLL_WAIT             232
    #define SYSCALL_EPOLL_CTL              233
    #define SYSCALL_INOTIFY_ADD_WATCH      254
    #define SYSCALL_INOTIFY_RM_WATCH       255
    #define SYSCALL_OPENAT                 257
    #define SYSCALL_MKDIRAT                258
    #define SYSCALL_MKNODAT                259
    #define SYSCALL_FCHOWNAT               260
    #define SYSCALL_FUTIMESAT              261
    #define SYSCALL_NEWFSTATAT             262
    #define SYSCALL_UNLINKAT               263
    #define SYSCALL_SYMLINKAT              266
    #define SYSCALL_READLINKAT             267
    #define SYSCALL_FCHMODAT               268
    #define SYSCALL_FACCESSAT              269
    #define SYSCALL_SYNC_FILE_RANGE        277
    #define SYSCALL_VMSPLICE               278
    #define SYSCALL_UTIMENSAT              280
    #define SYSCALL_EPOLL_PWAIT            281
    #define SYSCALL_SIGNALFD               282
    #define SYSCALL_FALLOCATE              285
    #define SYSCALL_TIMERFD_SETTIME        286
    #define SYSCALL_TIMERFD_GETTIME        287
    #define SYSCALL_ACCEPT4                288
    #define SYSCALL_SIGNALFD4              289
    #define SYSCALL_DUP3                   292
    #define SYSCALL_PREADV                 295
    #define SYSCALL_PWRITEV                296
    #define SYSCALL_PERF_EVENT_OPEN        298
    #define SYSCALL_RECVMMSG               299
    #define SYSCALL_NAME_TO_HANDLE_AT      303
    #define SYSCALL_OPEN_BY_HANDLE_AT      304
    #define SYSCALL_SYNCFS                 306
    #define SYSCALL_SENDMMSG               307
    #define SYSCALL_SETNS                  308
    #define SYSCALL_FINIT_MODULE           313
    #define SYSCALL_EXECVEAT               322
    #define SYSCALL_PREADV2                327
    #define SYSCALL_PWRITEV2               328
    #define SYSCALL_PKEY_MPROTECT          329
    #define SYSCALL_STATX                  332
    #define SYSCALL_PIDFD_SEND_SIGNAL      424
    #define SYSCALL_IO_URING_ENTER         426
    #define SYSCALL_IO_URING_REGISTER      427
    #define SYSCALL_OPEN_TREE              428
    #define SYSCALL_FSCONFIG               431
    #define SYSCALL_FSMOUNT                432
    #define SYSCALL_FSPICK                 433
    #define SYSCALL_OPENAT2                437
    #define SYSCALL_FACCESSAT2             439
    #define SYSCALL_PROCESS_MADVISE        440
    #define SYSCALL_EPOLL_PWAIT2           441
    #define SYSCALL_MOUNT_SETATTR          442
    #define SYSCALL_QUOTACTL_FD            443
    #define SYSCALL_LANDLOCK_ADD_RULE      445
    #define SYSCALL_LANDLOCK_RESTRICT_SELF 446
    #define SYSCALL_PROCESS_MRELEASE       448

#elif defined(bpf_target_arm64)
    #define SYSCALL_READ                   63
    #define SYSCALL_WRITE                  64
    #define SYSCALL_OPEN                   UNDEFINED_SYSCALL
    #define SYSCALL_CLOSE                  57
    #define SYSCALL_FSTAT                  80
    #define SYSCALL_LSEEK                  62
    #define SYSCALL_MMAP                   222
    #define SYSCALL_MPROTECT               226
    #define SYSCALL_RT_SIGRETURN           139
    #define SYSCALL_IOCTL                  29
    #define SYSCALL_PREAD64                67
    #define SYSCALL_PWRITE64               68
    #define SYSCALL_READV                  65
    #define SYSCALL_WRITEV                 66
    #define SYSCALL_DUP                    23
    #define SYSCALL_DUP2                   UNDEFINED_SYSCALL
    #define SYSCALL_SOCKET                 198
    #define SYSCALL_CONNECT                203
    #define SYSCALL_ACCEPT                 202
    #define SYSCALL_SENDTO                 206
    #define SYSCALL_RECVFROM               207
    #define SYSCALL_SENDMSG                211
    #define SYSCALL_RECVMSG                212
    #define SYSCALL_SHUTDOWN               210
    #define SYSCALL_BIND                   200
    #define SYSCALL_LISTEN                 201
    #define SYSCALL_GETSOCKNAME            204
    #define SYSCALL_GETPEERNAME            205
    #define SYSCALL_SETSOCKOPT             208
    #define SYSCALL_GETSOCKOPT             209
    #define SYSCALL_EXECVE                 221
    #define SYSCALL_EXIT                   93
    #define SYSCALL_FCNTL                  25
    #define SYSCALL_FLOCK                  32
    #define SYSCALL_FSYNC                  82
    #define SYSCALL_FDATASYNC              83
    #define SYSCALL_FTRUNCATE              46
    #define SYSCALL_GETDENTS               UNDEFINED_SYSCALL
    #define SYSCALL_FCHDIR                 50
    #define SYSCALL_FCHMOD                 52
    #define SYSCALL_FCHOWN                 55
    #define SYSCALL_FSTATFS                44
    #define SYSCALL_READAHEAD              213
    #define SYSCALL_FSETXATTR              7
    #define SYSCALL_FGETXATTR              10
    #define SYSCALL_FLISTXATTR             13
    #define SYSCALL_FREMOVEXATTR           16
    #define SYSCALL_GETDENTS64             61
    #define SYSCALL_FADVISE64              223
    #define SYSCALL_EXIT_GROUP             94
    #define SYSCALL_EPOLL_WAIT             UNDEFINED_SYSCALL
    #define SYSCALL_EPOLL_CTL              21
    #define SYSCALL_INOTIFY_ADD_WATCH      27
    #define SYSCALL_INOTIFY_RM_WATCH       28
    #define SYSCALL_OPENAT                 56
    #define SYSCALL_MKDIRAT                34
    #define SYSCALL_MKNODAT                33
    #define SYSCALL_FCHOWNAT               54
    #define SYSCALL_FUTIMESAT              UNDEFINED_SYSCALL
    #define SYSCALL_NEWFSTATAT             UNDEFINED_SYSCALL
    #define SYSCALL_UNLINKAT               35
    #define SYSCALL_SYMLINKAT              36
    #define SYSCALL_READLINKAT             78
    #define SYSCALL_FCHMODAT               53
    #define SYSCALL_FACCESSAT              48
    #define SYSCALL_SYNC_FILE_RANGE        84
    #define SYSCALL_VMSPLICE               75
    #define SYSCALL_UTIMENSAT              88
    #define SYSCALL_EPOLL_PWAIT            22
    #define SYSCALL_SIGNALFD               UNDEFINED_SYSCALL
    #define SYSCALL_FALLOCATE              47
    #define SYSCALL_TIMERFD_SETTIME        86
    #define SYSCALL_TIMERFD_GETTIME        87
    #define SYSCALL_ACCEPT4                242
    #define SYSCALL_SIGNALFD4              74
    #define SYSCALL_DUP3                   24
    #define SYSCALL_PREADV                 69
    #define SYSCALL_PWRITEV                70
    #define SYSCALL_PERF_EVENT_OPEN        241
    #define SYSCALL_RECVMMSG               243
    #define SYSCALL_NAME_TO_HANDLE_AT      264
    #define SYSCALL_OPEN_BY_HANDLE_AT      265
    #define SYSCALL_SYNCFS                 267
    #define SYSCALL_SENDMMSG               269
    #define SYSCALL_SETNS                  268
    #define SYSCALL_FINIT_MODULE           273
    #define SYSCALL_EXECVEAT               281
    #define SYSCALL_PREADV2                286
    #define SYSCALL_PWRITEV2               287
    #define SYSCALL_PKEY_MPROTECT          288
    #define SYSCALL_STATX                  291
    #define SYSCALL_PIDFD_SEND_SIGNAL      424
    #define SYSCALL_IO_URING_ENTER         426
    #define SYSCALL_IO_URING_REGISTER      427
    #define SYSCALL_OPEN_TREE              428
    #define SYSCALL_FSCONFIG               431
    #define SYSCALL_FSMOUNT                432
    #define SYSCALL_FSPICK                 433
    #define SYSCALL_OPENAT2                437
    #define SYSCALL_FACCESSAT2             439
    #define SYSCALL_PROCESS_MADVISE        440
    #define SYSCALL_EPOLL_PWAIT2           441
    #define SYSCALL_MOUNT_SETATTR          442
    #define SYSCALL_QUOTACTL_FD            443
    #define SYSCALL_LANDLOCK_ADD_RULE      445
    #define SYSCALL_LANDLOCK_RESTRICT_SELF 446
    #define SYSCALL_PROCESS_MRELEASE       448
#endif

enum event_id_e
{
    // Net events IDs
    NET_PACKET_BASE = 700,
    NET_PACKET_IP,
    NET_PACKET_TCP,
    NET_PACKET_UDP,
    NET_PACKET_ICMP,
    NET_PACKET_ICMPV6,
    NET_PACKET_DNS,
    NET_PACKET_HTTP,
    NET_PACKET_CAP_BASE,
    MAX_NET_EVENT_ID,
    // Common event IDs
    RAW_SYS_ENTER,
    RAW_SYS_EXIT,
    SCHED_PROCESS_FORK,
    SCHED_PROCESS_EXEC,
    SCHED_PROCESS_EXIT,
    SCHED_SWITCH,
    DO_EXIT,
    CAP_CAPABLE,
    VFS_WRITE,
    VFS_WRITEV,
    VFS_READ,
    VFS_READV,
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
    SECURITY_SOCKET_SETSOCKOPT,
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
    SECURITY_INODE_RENAME,
    DO_SIGACTION,
    BPF_ATTACH,
    KALLSYMS_LOOKUP_NAME,
    DO_MMAP,
    PRINT_MEM_DUMP,
    MAX_EVENT_ID,
};

#define CAPTURE_IFACE (1 << 0)
#define TRACE_IFACE   (1 << 1)

#define OPT_EXEC_ENV              (1 << 0)
#define OPT_CAPTURE_FILES         (1 << 1)
#define OPT_EXTRACT_DYN_CODE      (1 << 2)
#define OPT_CAPTURE_STACK_TRACES  (1 << 3)
#define OPT_CAPTURE_MODULES       (1 << 4)
#define OPT_CGROUP_V1             (1 << 5)
#define OPT_PROCESS_INFO          (1 << 6)
#define OPT_TRANSLATE_FD_FILEPATH (1 << 7)

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
#define FILTER_BIN_PATH_ENABLED  (1 << 23)
#define FILTER_BIN_PATH_OUT      (1 << 24)

#define FILTER_MAX_NOT_SET 0
#define FILTER_MIN_NOT_SET ULLONG_MAX

#define DEV_NULL_STR 0

#define CONT_ID_LEN          12
#define CONT_ID_MIN_FULL_LEN 64

enum context_flags_e
{
    CONTAINER_STARTED_FLAG = (1 << 0)
};

enum container_state_e
{
    CONTAINER_UNKNOWN = 0, // mark that container state is unknown
    CONTAINER_EXISTED,     // container existed before tracee was started
    CONTAINER_CREATED,     // new cgroup path created
    CONTAINER_STARTED      // a process in the cgroup executed a new binary
};

#define PACKET_MIN_SIZE 40

#ifndef CORE
    #if LINUX_VERSION_CODE <                                                                       \
        KERNEL_VERSION(5, 2, 0) // lower values in old kernels (instr lim is 4096)
        #define MAX_STR_ARR_ELEM      38
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
    #define MAX_STR_ARR_ELEM      38 // TODO: turn this into global variables set w/ libbpfgo
    #define MAX_ARGS_STR_ARR_ELEM 15
    #define MAX_PATH_PREF_SIZE    64
    #define MAX_PATH_COMPONENTS   20
    #define MAX_BIN_CHUNKS        110
#endif

#if defined(bpf_target_x86)
    #define NUMBER_OF_SYSCALLS_TO_CHECK 18
#elif defined(bpf_target_arm64)
    #define NUMBER_OF_SYSCALLS_TO_CHECK 14
#else
    #define NUMBER_OF_SYSCALLS_TO_CHECK 0
#endif

#define MAX_CACHED_PATH_SIZE 64

enum signal_handling_method_e
{
#ifdef CORE
    SIG_DFL,
    SIG_IGN,
#endif
    SIG_HND = 2 // Doesn't exist in the kernel, but signifies that the method is through
                // user-defined handler
};

enum bpf_write_user_e
{
    WRITE_USER_FALSE,
    WRITE_USER_TRUE,
    WRITE_USER_UNKNOWN
};

enum perf_type_e
{
    PERF_TRACEPOINT,
    PERF_KPROBE,
    PERF_KRETPROBE,
    PERF_UPROBE,
    PERF_URETPROBE
};

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

    #define READ_KERN_STR_INTO(dst, src) bpf_probe_read_str((void *) &dst, sizeof(dst), src)

    #define READ_USER(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_probe_read_user((void *) &_val, sizeof(_val), &ptr);                               \
            _val;                                                                                  \
        })

    #define BPF_READ(src, a, ...)                                                                  \
        ({                                                                                         \
            ___type((src), a, ##__VA_ARGS__) __r;                                                  \
            BPF_PROBE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);                                    \
            __r;                                                                                   \
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

    #define READ_KERN_STR_INTO(dst, src) bpf_core_read_str((void *) &dst, sizeof(dst), src)

    #define READ_USER(ptr)                                                                         \
        ({                                                                                         \
            typeof(ptr) _val;                                                                      \
            __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
            bpf_core_read_user((void *) &_val, sizeof(_val), &ptr);                                \
            _val;                                                                                  \
        })

    #define BPF_READ(src, a, ...)                                                                  \
        ({                                                                                         \
            ___type((src), a, ##__VA_ARGS__) __r;                                                  \
            BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);                                     \
            __r;                                                                                   \
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
    u32 flags;
} task_context_t;

typedef struct event_context {
    u64 ts; // Timestamp
    task_context_t task;
    u32 eventid;
    u32 padding; // free for further use
    u64 matched_scopes;
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

typedef struct fd_arg_task {
    u32 pid;
    u32 tid;
    int fd;
} fd_arg_task_t;

typedef struct fd_arg_path {
    char path[MAX_CACHED_PATH_SIZE];
} fd_arg_path_t;

typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced;  // indicates that syscall_data is valid
    bool recompute_scope; // recompute matched_scopes (new task/context changed/policy changed)
    u64 matched_scopes;   // cached bitmap of scopes this task matched
    u8 container_state;   // the state of the container the task resides in
} task_info_t;

typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_info_t;

typedef struct binary {
    u32 mnt_id;
    char path[MAX_BIN_PATH_SIZE];
} binary_t;

typedef struct io_data {
    void *ptr;
    unsigned long len;
    bool is_buf;
} io_data_t;

typedef struct proc_info {
    bool new_proc;        // set if this process was started after tracee. Used with new_pid filter
    u64 follow_in_scopes; // set if this process was traced before. Used with the follow filter
    struct binary binary;
    u32 binary_no_mnt; // used in binary lookup when we don't care about mount ns. always 0.
    file_info_t interpreter;
} proc_info_t;

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
    u32 cgroup_v1_hid;
    u32 padding; // free for further use
    // enabled scopes bitmask per filter
    u64 uid_filter_enabled_scopes;
    u64 pid_filter_enabled_scopes;
    u64 mnt_ns_filter_enabled_scopes;
    u64 pid_ns_filter_enabled_scopes;
    u64 uts_ns_filter_enabled_scopes;
    u64 comm_filter_enabled_scopes;
    u64 cgroup_id_filter_enabled_scopes;
    u64 cont_filter_enabled_scopes;
    u64 new_cont_filter_enabled_scopes;
    u64 new_pid_filter_enabled_scopes;
    u64 proc_tree_filter_enabled_scopes;
    u64 bin_path_filter_enabled_scopes;
    u64 follow_filter_enabled_scopes;
    // filter_out bitmask per filter
    u64 uid_filter_out_scopes;
    u64 pid_filter_out_scopes;
    u64 mnt_ns_filter_out_scopes;
    u64 pid_ns_filter_out_scopes;
    u64 uts_ns_filter_out_scopes;
    u64 comm_filter_out_scopes;
    u64 cgroup_id_filter_out_scopes;
    u64 cont_filter_out_scopes;
    u64 new_cont_filter_out_scopes;
    u64 new_pid_filter_out_scopes;
    u64 proc_tree_filter_out_scopes;
    u64 bin_path_filter_out_scopes;
    // bitmask with scopes that have at least one filter enabled
    u64 enabled_scopes;
    // global min max
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;
} config_entry_t;

typedef struct netconfig_entry {
    u32 capture_length; // amount of network packet payload to capture (pcap)
} netconfig_entry_t;

typedef struct event_data {
    event_context_t context;
    char args[ARGS_BUF_SIZE];
    u32 buf_off;
    struct task_struct *task;
} event_data_t;

#define MAX_EVENT_SIZE sizeof(event_context_t) + ARGS_BUF_SIZE

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

typedef struct bpf_attach {
    enum bpf_write_user_e write_user;
} bpf_attach_t;

typedef struct equality {
    // bitmask with scopes on which a equal '=' filter is set
    // its bit value will depend on the filter's equality precedence order
    u64 equal_in_scopes;
    // bitmask with scopes on which a filter equality is set
    u64 equality_set_in_scopes;
} eq_t;

enum bpf_log_level
{
    BPF_LOG_LVL_DEBUG = -1,
    BPF_LOG_LVL_INFO,
    BPF_LOG_LVL_WARN,
    BPF_LOG_LVL_ERROR,
};

enum bpf_log_id
{
    BPF_LOG_ID_UNSPEC = 0U, // enforce enum to u32

    // tracee functions
    BPF_LOG_ID_INIT_CONTEXT,

    // bpf helpers functions
    BPF_LOG_ID_MAP_LOOKUP_ELEM,
    BPF_LOG_ID_MAP_UPDATE_ELEM,
    BPF_LOG_ID_MAP_DELETE_ELEM,
    BPF_LOG_ID_GET_CURRENT_COMM,
    BPF_LOG_ID_TAIL_CALL,
    BPF_LOG_ID_MEM_READ,
};

#define BPF_MAX_LOG_FILE_LEN 72

typedef struct bpf_log {
    s64 ret; // return value
    u32 cpu;
    u32 line;                        // line number
    char file[BPF_MAX_LOG_FILE_LEN]; // filename
} bpf_log_t;

typedef struct bpf_log_count {
    u32 count;
    u64 ts; // timestamp
} bpf_log_count_t;

typedef struct bpf_log_output {
    enum bpf_log_id id; // type
    enum bpf_log_level level;
    u32 count;
    u32 padding;
    struct bpf_log log;
} bpf_log_output_t;

typedef union scratch {
    bpf_log_output_t log_output;
    proc_info_t proc_info;
    task_info_t task_info;
} scratch_t;

typedef struct program_data {
    config_entry_t *config;
    task_info_t *task_info;
    event_data_t *event;
    scratch_t *scratch;
    void *ctx;
} program_data_t;

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

    #define get_type_size(x)            sizeof(x)
    #define get_node_addr(array, index) &array[index]

#endif

// EBPF MAPS DECLARATIONS --------------------------------------------------------------------------

// clang-format off

BPF_HASH(kconfig_map, u32, u32, 10240);                            // kernel config variables
BPF_HASH(containers_map, u32, u8, 10240);                          // map cgroup id to container status {EXISTED, CREATED, STARTED}
BPF_HASH(args_map, u64, args_t, 1024);                             // persist args between function entry and return
BPF_HASH(uid_filter, u32, eq_t, 256);                              // filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, eq_t, 256);                              // filter events by PID
BPF_HASH(mnt_ns_filter, u64, eq_t, 256);                           // filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, eq_t, 256);                           // filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, eq_t, 256);               // filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, eq_t, 256);                 // filter events by command name
BPF_HASH(cgroup_id_filter, u32, eq_t, 256);                        // filter events by cgroup id
BPF_HASH(binary_filter, binary_t, eq_t, 256);                      // filter events by binary path and mount namespace
BPF_HASH(events_map, u32, u64, MAX_EVENT_ID);                      // map to persist event configuration data (currently submit scopes)
BPF_HASH(bin_args_map, u64, bin_args_t, 256);                      // persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32, 1024);                        // map 32bit to 64bit syscalls
BPF_HASH(params_types_map, u32, u64, 1024);                        // encoded parameters types for event
BPF_HASH(process_tree_map, u32, eq_t, 10240);                      // filter events by the ancestry of the traced process
BPF_LRU_HASH(proc_info_map, u32, proc_info_t, 10240);              // holds data for every process
BPF_LRU_HASH(task_info_map, u32, task_info_t, 10240);              // holds data for every task
BPF_HASH(ksymbols_map, ksym_name_t, u64, 1024);                    // holds the addresses of some kernel symbols
BPF_HASH(syscalls_to_check_map, int, u64, 256);                    // syscalls to discover
BPF_ARRAY(config_map, config_entry_t, 1);                          // various configurations
BPF_ARRAY(netconfig_map, netconfig_entry_t, 1);                    // network related configurations
BPF_ARRAY(file_filter, path_filter_t, 3);                          // filter vfs_write events
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);                        // percpu global buffer variables
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);                         // store programs for tail calls
BPF_PROG_ARRAY(prog_array_tp, MAX_TAIL_CALL);                      // store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);                     // store syscall specific programs for tail calls from sys_enter
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);                      // store syscall specific programs for tail calls from sys_exit
BPF_PROG_ARRAY(sys_enter_submit_tail, MAX_EVENT_ID);               // store program for submitting syscalls from sys_enter
BPF_PROG_ARRAY(sys_exit_submit_tail, MAX_EVENT_ID);                // store program for submitting syscalls from sys_exit
BPF_PROG_ARRAY(sys_enter_init_tail, MAX_EVENT_ID);                 // store program for performing syscall tracking logic in sys_enter
BPF_PROG_ARRAY(sys_exit_init_tail, MAX_EVENT_ID);                  // store program for performing syscall tracking logic in sys_exits
BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);             // store stack traces
BPF_HASH(module_init_map, u32, kmod_data_t, 256);                  // holds module information between
BPF_LRU_HASH(fd_arg_path_map, fd_arg_task_t, fd_arg_path_t, 1024); // store fds paths by task
BPF_LRU_HASH(bpf_attach_map, u32, bpf_attach_t, 1024);             // holds bpf prog info
BPF_LRU_HASH(bpf_attach_tmp_map, u32, bpf_attach_t, 1024);         // temporarily hold bpf_attach_t
BPF_PERCPU_ARRAY(event_data_map, event_data_t, 1);                 // persist event related data
BPF_HASH(logs_count, bpf_log_t, bpf_log_count_t, 4096);            // logs count
BPF_PERCPU_ARRAY(scratch_map, scratch_t, 1);                       // scratch space to avoid allocating stuff on the stack
// clang-format on

// EBPF PERF BUFFERS -------------------------------------------------------------------------------

BPF_PERF_OUTPUT(logs, 1024);        // logs submission
BPF_PERF_OUTPUT(events, 1024);      // events submission
BPF_PERF_OUTPUT(file_writes, 1024); // file writes events submission
BPF_PERF_OUTPUT(net_events, 1024);  // network events submission

// FUNCTIONS DECLARATIONS --------------------------------------------------------------------------

static __always_inline void *get_path_str(struct path *path);

// HELPERS: LOGS -----------------------------------------------------------------------------------

static __always_inline void do_tracee_log(
    void *ctx, enum bpf_log_level level, enum bpf_log_id id, s64 ret, u32 line, void *file)
{
    if (!ctx || !file)
        return;

    u32 zero = 0;
    bpf_log_output_t *log_output = bpf_map_lookup_elem(&scratch_map, &zero);
    if (unlikely(log_output == NULL))
        return;

    log_output->level = level;
    log_output->id = id;

    log_output->log.ret = ret;
    log_output->log.cpu = bpf_get_smp_processor_id();
    log_output->log.line = line;

    u64 fsize = __builtin_strlen(file);
    if (unlikely(fsize >= BPF_MAX_LOG_FILE_LEN))
        fsize = BPF_MAX_LOG_FILE_LEN - 1;
    __builtin_memcpy(log_output->log.file, file, fsize);
    log_output->log.file[fsize] = '\0';

    bpf_log_count_t counter_buf = {};
    counter_buf.count = 1;
    counter_buf.ts = bpf_ktime_get_ns(); // store the current ts
    u64 ts_prev = 0;

    bpf_log_count_t *counter = bpf_map_lookup_elem(&logs_count, &log_output->log);
    if (likely(counter != NULL)) {
        ts_prev = counter->ts; // store previous ts

        counter->count += 1;
        counter->ts = counter_buf.ts; // set to current ts
    } else {
        counter = &counter_buf;
        bpf_map_update_elem(&logs_count, &log_output->log, counter, BPF_ANY);
    }

    // submit log when its cpu occurrence time diff is greater than 2s
    if ((counter->ts - ts_prev) > (u64) 2000000000) {
        log_output->count = counter->count;
        bpf_perf_event_output(ctx, &logs, BPF_F_CURRENT_CPU, log_output, sizeof(*log_output));
        counter->count = 0; // reset, assuming that the consumer is incrementing
    }
}

#define tracee_log(ctx, level, id, ret) do_tracee_log(ctx, level, id, ret, __LINE__, __FILE__);

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

static __always_inline u32 get_pid_ns_for_children_id(struct nsproxy *ns)
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

static __always_inline u32 get_task_pid_ns_for_children_id(struct task_struct *task)
{
    return get_pid_ns_for_children_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    struct pid_namespace *ns = NULL;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
    #else
    pid = READ_KERN(task->thread_pid);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = READ_KERN(t->pids[PIDTYPE_PID].pid);
    } else {
        pid = READ_KERN(task->thread_pid);
    }
#endif

    level = READ_KERN(pid->level);
    ns = READ_KERN(pid->numbers[level].ns);
    return READ_KERN(ns->ns.inum);
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

static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
    #else
    pid = READ_KERN(task->thread_pid);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = READ_KERN(t->pids[PIDTYPE_PID].pid);
    } else {
        pid = READ_KERN(task->thread_pid);
    }
#endif

    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    return get_task_pid_vnr(real_parent);
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

static __always_inline int get_syscall_id_from_regs(struct pt_regs *regs)
{
#if defined(bpf_target_x86)
    int id = READ_KERN(regs->orig_ax);
#elif defined(bpf_target_arm64)
    int id = READ_KERN(regs->syscallno);
#endif
    return id;
}

static __always_inline struct pt_regs *get_task_pt_regs(struct task_struct *task)
{
// THREAD_SIZE here is statistically defined and assumed to work for 4k page sizes.
#if defined(bpf_target_x86)
    void *__ptr = READ_KERN(task->stack) + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *) __ptr) - 1;
#elif defined(bpf_target_arm64)
    return ((struct pt_regs *) (THREAD_SIZE + READ_KERN(task->stack)) - 1);
#endif
}

static __always_inline int get_task_syscall_id(struct task_struct *task)
{
    struct pt_regs *regs = get_task_pt_regs(task);
    return get_syscall_id_from_regs(regs);
}

// HELPERS: VFS ------------------------------------------------------------------------------------

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

static __always_inline struct in6_addr get_sock_v6_daddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_daddr);
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

static __always_inline void *get_stext_addr()
{
    char start_text_sym[7] = "_stext";
    return get_symbol_addr(start_text_sym);
}

static __always_inline void *get_etext_addr()
{
    char end_text_sym[7] = "_etext";
    return get_symbol_addr(end_text_sym);
}

// INTERNAL: CONTEXT -------------------------------------------------------------------------------

static __always_inline int
init_context(void *ctx, event_context_t *context, struct task_struct *task, u32 options)
{
    long ret = 0;
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
    context->task.flags = 0;
    __builtin_memset(context->task.comm, 0, sizeof(context->task.comm));
    ret = bpf_get_current_comm(&context->task.comm, sizeof(context->task.comm));
    if (unlikely(ret < 0)) {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_GET_CURRENT_COMM, ret);
        return -1;
    }

    char *uts_name = get_task_uts_name(task);
    if (uts_name) {
        __builtin_memset(context->task.uts_name, 0, sizeof(context->task.uts_name));
        bpf_probe_read_str(&context->task.uts_name, TASK_COMM_LEN, uts_name);
    }
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

static __always_inline task_info_t *init_task_info(u32 tid, u32 pid, scratch_t *scratch)
{
    int zero = 0;

    // allow caller to specify a stack/map based scratch_t pointer
    if (scratch == NULL) {
        scratch = bpf_map_lookup_elem(&scratch_map, &zero);
        if (unlikely(scratch == NULL))
            return NULL;
    }

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &pid);
    if (proc_info == NULL) {
        scratch->proc_info.new_proc = false;
        scratch->proc_info.follow_in_scopes = 0;
        scratch->proc_info.binary.mnt_id = 0;
        scratch->proc_info.binary_no_mnt = 0;
        __builtin_memset(scratch->proc_info.binary.path, 0, MAX_BIN_PATH_SIZE);
        bpf_map_update_elem(&proc_info_map, &pid, &scratch->proc_info, BPF_NOEXIST);
    }

    scratch->task_info.syscall_traced = false;
    scratch->task_info.recompute_scope = true;
    scratch->task_info.container_state = CONTAINER_UNKNOWN;
    bpf_map_update_elem(&task_info_map, &tid, &scratch->task_info, BPF_NOEXIST);

    return bpf_map_lookup_elem(&task_info_map, &tid);
}

static __always_inline bool context_changed(task_context_t *old, task_context_t *new)
{
    return (old->cgroup_id != new->cgroup_id) || old->uid != new->uid ||
           old->mnt_id != new->mnt_id || old->pid_id != new->pid_id ||
           *(u64 *) old->comm != *(u64 *) new->comm ||
           *(u64 *) &old->comm[8] != *(u64 *) &new->comm[8] ||
           *(u64 *) old->uts_name != *(u64 *) new->uts_name ||
           *(u64 *) &old->uts_name[8] != *(u64 *) &new->uts_name[8];
}

// clang-format off
static __always_inline int init_program_data(program_data_t *p, void *ctx)
{
    long ret = 0;
    int zero = 0;

    // allow caller to specify a stack/map based event_data_t pointer
    if (p->event == NULL) {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->event->task = (struct task_struct *) bpf_get_current_task();
    ret = init_context(ctx, &p->event->context, p->event->task, p->config->options);
    if (unlikely(ret < 0)) {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_INIT_CONTEXT, ret);
        return 0;
    }

    p->ctx = ctx;
    p->event->buf_off = 0;

    bool container_lookup_required = true;

    p->task_info = bpf_map_lookup_elem(&task_info_map, &p->event->context.task.host_tid);
    if (unlikely(p->task_info == NULL)) {
        p->task_info = init_task_info(
            p->event->context.task.host_tid,
            p->event->context.task.host_pid,
            p->scratch
        );
        if (unlikely(p->task_info == NULL)) {
            return 0;
        }
        // just initialized task info: recompute_scope is already set to true
        goto out;
    }

    // in some places we don't call should_trace() (e.g. sys_exit) which also initializes
    // matched_scopes. Use previously found scopes then to initialize it.
    p->event->context.matched_scopes = p->task_info->matched_scopes;

    // check if we need to recompute scope due to context change
    if (context_changed(&p->task_info->context, &p->event->context.task))
        p->task_info->recompute_scope = true;

    u8 container_state = p->task_info->container_state;

    // if task is already part of a container: no need to check if state changed
    switch (container_state) {
        case CONTAINER_STARTED:
        case CONTAINER_EXISTED:
            p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
            container_lookup_required = false;
    }

out:
    if (container_lookup_required) {
        u32 cgroup_id_lsb = p->event->context.task.cgroup_id;
        u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);

        if (state != NULL) {
            p->task_info->container_state = *state;
            switch (*state) {
                case CONTAINER_STARTED:
                case CONTAINER_EXISTED:
                    p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
            }
        }
    }

    // update task_info with the new context
    bpf_probe_read(&p->task_info->context, sizeof(task_context_t), &p->event->context.task);

    return 1;
}
// clang-format on

static __always_inline int init_tailcall_program_data(program_data_t *p, void *ctx)
{
    u32 zero = 0;

    p->ctx = ctx;

    p->event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (unlikely(p->event == NULL))
        return 0;

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->task_info = bpf_map_lookup_elem(&task_info_map, &p->event->context.task.host_tid);
    if (unlikely(p->task_info == NULL)) {
        return 0;
    }

    return 1;
}

// INTERNAL: FILTERING -----------------------------------------------------------------------------

static __always_inline u64
uint_filter_range_matches(u64 filter_out_scopes, void *filter_map, u64 value, u64 max, u64 min)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;
    eq_t *equality = bpf_map_lookup_elem(filter_map, &value);
    if (equality != NULL) {
        equal_in_scopes = equality->equal_in_scopes;
        equality_set_in_scopes = equality->equality_set_in_scopes;
    }

    if ((max != FILTER_MAX_NOT_SET) && (value >= max))
        return equal_in_scopes;

    if ((min != FILTER_MIN_NOT_SET) && (value <= min))
        return equal_in_scopes;

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

static __always_inline u64 binary_filter_matches(u64 filter_out_scopes, proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;
    eq_t *equality = bpf_map_lookup_elem(&binary_filter, proc_info->binary.path);
    if (equality == NULL) {
        // lookup by binary path and mount namespace
        equality = bpf_map_lookup_elem(&binary_filter, &proc_info->binary);
    }
    if (equality != NULL) {
        equal_in_scopes = equality->equal_in_scopes;
        equality_set_in_scopes = equality->equality_set_in_scopes;
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

static __always_inline u64 equality_filter_matches(u64 filter_out_scopes,
                                                   void *filter_map,
                                                   void *key)
{
    // check compute_scopes() for initial info
    //
    // e.g.: cmdline: -t 2:comm=who -t 3:comm=ping -t 4:comm!=who
    //
    // filter_out_scopes = 0000 1000, since scope 4 has "not equal" for comm filter
    // filter_map        = comm_filter
    // key               = "who" | "ping"
    //
    // ---
    //
    // considering an event from "who" command
    //
    // equal_in_scopes   = 0000 0010, since scope 2 has "equal" for comm filter
    // equality_set_in_scopes = 0000 1010, since scope 2 and 4 are set for comm filter
    //
    // return            = equal_in_scopes | (filter_out_scopes & equality_set_in_scopes)
    //                     0000 0010 |
    //                     (0000 1000 & 1111 0101) -> 0000 0000
    //
    //                     0000 0010 |
    //                     0000 0000
    //                     ---------
    //                     0000 0010 = (scope 2 matched)
    //
    // considering an event from "ping" command
    //
    // equal_in_scopes   = 0000 0100, since scope 3 has "equal" for comm filter
    // equality_set_in_scopes = 0000 0100, since scope 3 is set for comm filter
    //
    // return            = equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes)
    //                     0000 0100 |
    //                     (0000 1000 & 0000 0100) -> 0000 0000
    //
    //                     0000 0100 |
    //                     0000 0000
    //                     ---------
    //                     0000 0100 = (scope 3 matched)

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;
    eq_t *equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL) {
        equal_in_scopes = equality->equal_in_scopes;
        equality_set_in_scopes = equality->equality_set_in_scopes;
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

static __always_inline u64 bool_filter_matches(u64 filter_out_scopes, bool val)
{
    // check compute_scopes() for initial info
    //
    // e.g.: cmdline: -t 5:container
    //
    // considering an event from a container
    //
    //   filter_out_scopes = 0000 0000
    //   val               = true
    //   return            = 0000 0000 ^
    //                       1111 1111 <- ~0ULL
    //                       ---------
    //                       1111 1111
    //
    // considering an event not from a container
    //
    //   filter_out_scopes = 0000 0000
    //   val               = false
    //   return            = 0000 0000 ^
    //                       0000 0000
    //                       ---------
    //                       0000 0000

    return filter_out_scopes ^ (val ? ~0ULL : 0);
}

static __always_inline u64 compute_scopes(program_data_t *p)
{
    task_context_t *context = &p->task_info->context;
    u64 res = ~0ULL;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid) {
        return 0;
    }

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &context->host_pid);
    if (proc_info == NULL) {
        // entry should exist in proc_map (init_program_data should have set it otherwise)
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(p->event->ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    if (p->config->cont_filter_enabled_scopes) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 filter_out_scopes = p->config->cont_filter_out_scopes;
        u64 mask = ~p->config->cont_filter_enabled_scopes;
        // For scopes which has this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(filter_out_scopes, is_container) | mask;
    }

    if (p->config->new_cont_filter_enabled_scopes) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 filter_out_scopes = p->config->new_cont_filter_out_scopes;
        u64 mask = ~p->config->new_cont_filter_enabled_scopes;
        res &= bool_filter_matches(filter_out_scopes, is_new_container) | mask;
    }

    if (p->config->pid_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->pid_filter_out_scopes;
        u64 mask = ~p->config->pid_filter_enabled_scopes;
        u64 max = p->config->pid_max;
        u64 min = p->config->pid_min;
        // the user might have given us a tid - check for it too
        res &=
            uint_filter_range_matches(filter_out_scopes, &pid_filter, context->host_pid, max, min) |
            uint_filter_range_matches(filter_out_scopes, &pid_filter, context->host_tid, max, min) |
            mask;
    }

    if (p->config->new_pid_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->new_pid_filter_out_scopes;
        u64 mask = ~p->config->new_pid_filter_enabled_scopes;
        res &= bool_filter_matches(filter_out_scopes, proc_info->new_proc) | mask;
    }

    if (p->config->uid_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->uid_filter_out_scopes;
        u64 mask = ~p->config->uid_filter_enabled_scopes;
        u64 max = p->config->uid_max;
        u64 min = p->config->uid_min;
        res &= uint_filter_range_matches(filter_out_scopes, &uid_filter, context->uid, max, min) |
               mask;
    }

    if (p->config->mnt_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->mnt_ns_filter_out_scopes;
        u64 mask = ~p->config->mnt_ns_filter_enabled_scopes;
        u32 mnt_id = context->mnt_id;
        res &= equality_filter_matches(filter_out_scopes, &mnt_ns_filter, &mnt_id) | mask;
    }

    if (p->config->pid_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->pid_ns_filter_out_scopes;
        u64 mask = ~p->config->pid_ns_filter_enabled_scopes;
        u32 pid_id = context->pid_id;
        res &= equality_filter_matches(filter_out_scopes, &pid_ns_filter, &pid_id) | mask;
    }

    if (p->config->uts_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->uts_ns_filter_out_scopes;
        u64 mask = ~p->config->uts_ns_filter_enabled_scopes;
        res &=
            equality_filter_matches(filter_out_scopes, &uts_ns_filter, &context->uts_name) | mask;
    }

    if (p->config->comm_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->comm_filter_out_scopes;
        u64 mask = ~p->config->comm_filter_enabled_scopes;
        res &= equality_filter_matches(filter_out_scopes, &comm_filter, &context->comm) | mask;
    }

    if (p->config->proc_tree_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->proc_tree_filter_out_scopes;
        u64 mask = ~p->config->proc_tree_filter_enabled_scopes;
        res &= equality_filter_matches(filter_out_scopes, &process_tree_map, &context->host_pid) |
               mask;
    }

    if (p->config->cgroup_id_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->cgroup_id_filter_out_scopes;
        u64 mask = ~p->config->cgroup_id_filter_enabled_scopes;
        u64 cgroup_id_lsb = context->cgroup_id;
        res &= equality_filter_matches(filter_out_scopes, &cgroup_id_filter, &cgroup_id_lsb) | mask;
    }

    if (p->config->bin_path_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->bin_path_filter_out_scopes;
        u64 mask = ~p->config->bin_path_filter_enabled_scopes;
        res &= binary_filter_matches(filter_out_scopes, proc_info) | mask;
    }

    if (p->config->follow_filter_enabled_scopes) {
        // trace this proc anyway if follow was set by a scope
        res |= proc_info->follow_in_scopes & p->config->follow_filter_enabled_scopes;
    }

    // Make sure only enabled scopes are set in the bitmask (other bits are invalid)
    return res & p->config->enabled_scopes;
}

static __always_inline u64 should_trace(program_data_t *p)
{
    // use cache whenever possible
    if (p->task_info->recompute_scope) {
        p->task_info->matched_scopes = compute_scopes(p);
        p->task_info->recompute_scope = false;
    }

    p->event->context.matched_scopes = p->task_info->matched_scopes;

    return p->task_info->matched_scopes;
}

static __always_inline u64 should_submit(u32 event_id, event_context_t *ctx)
{
    // use a map only with no submit cache from config.
    // since this function is only ever called after a should_trace
    // and in the context of a submit program/tail_call, any preemptive
    // cache calculation before checking the map will 99% of times be
    // redundant.
    // a probe/tail call attach almost always implies at least one
    // scope requires the event to be submitted.
    u64 *event_scopes = bpf_map_lookup_elem(&events_map, &event_id);
    // if scopes not set, don't submit
    if (event_scopes == NULL) {
        return 0;
    }

    // align with previously matched scopes
    ctx->matched_scopes &= *event_scopes;

    return ctx->matched_scopes;
}

// INTERNAL: BUFFERS -------------------------------------------------------------------------------

static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

static __always_inline int save_to_submit_buf(event_data_t *event, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    barrier();
    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Satisfy verifier
    if (event->buf_off > ARGS_BUF_SIZE - (MAX_ELEMENT_SIZE + 1))
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(event->args[event->buf_off + 1]), size, ptr) == 0) {
        // We update buf_off only if all writes were successful
        event->buf_off += size + 1;
        event->context.argnum++;
        return 1;
    }

    return 0;
}

static __always_inline int save_bytes_to_buf(event_data_t *event, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][size][ ... bytes ... ]

    if (size == 0)
        return 0;

    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    if (event->buf_off > ARGS_BUF_SIZE - (sizeof(int) + 1))
        return 0;

    // Save size to buffer
    if (bpf_probe_read(&(event->args[event->buf_off + 1]), sizeof(int), &size) != 0) {
        return 0;
    }

    if (event->buf_off > ARGS_BUF_SIZE - (MAX_BYTES_ARR_SIZE + 1 + sizeof(int)))
        return 0;

    // Read bytes into buffer
    if (bpf_probe_read(&(event->args[event->buf_off + 1 + sizeof(int)]),
                       size & (MAX_BYTES_ARR_SIZE - 1),
                       ptr) == 0) {
        // We update buf_off only if all writes were successful
        event->buf_off += size + 1 + sizeof(int);
        event->context.argnum++;
        return 1;
    }

    return 0;
}

static __always_inline int save_str_to_buf(event_data_t *event, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]

    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Satisfy verifier for probe read
    if (event->buf_off > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
        return 0;

    // Read into buffer
    int sz =
        bpf_probe_read_str(&(event->args[event->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        barrier();
        // Satisfy verifier for probe read
        if (event->buf_off > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
            return 0;

        __builtin_memcpy(&(event->args[event->buf_off + 1]), &sz, sizeof(int));
        event->buf_off += sz + sizeof(int) + 1;
        event->context.argnum++;
        return 1;
    }

    return 0;
}

static __always_inline int
add_u64_elements_to_buf(event_data_t *event, const u64 __user *ptr, int len, volatile u32 count_off)
{
    // save count_off into a new variable to avoid verifier errors
    u32 off = count_off;
    u8 elem_num = 0;
#pragma unroll
    for (int i = 0; i < len; i++) {
        void *addr = &(event->args[event->buf_off]);
        if (event->buf_off > ARGS_BUF_SIZE - sizeof(u64))
            // not enough space - return
            goto out;
        if (bpf_probe_read(addr, sizeof(u64), (void *) &ptr[i]) != 0)
            goto out;
        elem_num++;
        event->buf_off += sizeof(u64);
    }
out:
    // save number of elements in the array
    if (off > (ARGS_BUF_SIZE - 1))
        return 0;

    u8 current_elem_num = event->args[off];
    event->args[off] = current_elem_num + elem_num;

    return 1;
}

static __always_inline int
save_u64_arr_to_buf(event_data_t *event, const u64 __user *ptr, int len, u8 index)
{
    // Data saved to submit buf: [index][u8 count][u64 1][u64 2][u64 3]...
    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Save space for number of elements (1 byte)
    event->buf_off += 1;
    volatile u32 orig_off = event->buf_off;
    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;
    event->args[event->buf_off] = 0;
    event->buf_off += 1;
    event->context.argnum++;

    return add_u64_elements_to_buf(event, ptr, len, orig_off);
}

static __always_inline int
save_str_arr_to_buf(event_data_t *event, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = event->buf_off + 1;
    event->buf_off += 2;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz =
            bpf_probe_read_str(&(event->args[event->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (event->buf_off > ARGS_BUF_SIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(event->args[event->buf_off]), sizeof(int), &sz);
            event->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz =
        bpf_probe_read_str(&(event->args[event->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (event->buf_off > ARGS_BUF_SIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(event->args[event->buf_off]), sizeof(int), &sz);
        event->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    if (orig_off > ARGS_BUF_SIZE - 1)
        return 0;
    event->args[orig_off] = elem_num;
    event->context.argnum++;
    return 1;
}

#define MAX_ARR_LEN 8192

static __always_inline int save_args_str_arr_to_buf(
    event_data_t *event, const char *start, const char *end, int elem_num, u8 index)
{
    // Data saved to submit buf: [index][len][arg_len][arg #][null delimited string array]
    // Note: This helper saves null (0x00) delimited string array into buf

    if (start >= end)
        return 0;

    int len = end - start;
    if (len > (MAX_ARR_LEN - 1))
        len = MAX_ARR_LEN - 1;

    // Save argument index
    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;
    event->args[event->buf_off] = index;

    // Satisfy validator for probe read
    if ((event->buf_off + 1) > ARGS_BUF_SIZE - sizeof(int))
        return 0;

    // Save array length
    bpf_probe_read(&(event->args[event->buf_off + 1]), sizeof(int), &len);

    // Satisfy validator for probe read
    if ((event->buf_off + 5) > ARGS_BUF_SIZE - sizeof(int))
        return 0;

    // Save number of arguments
    bpf_probe_read(&(event->args[event->buf_off + 5]), sizeof(int), &elem_num);

    // Satisfy validator for probe read
    if ((event->buf_off + 9) > ARGS_BUF_SIZE - MAX_ARR_LEN)
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(event->args[event->buf_off + 9]), len & (MAX_ARR_LEN - 1), start) == 0) {
        // We update buf_off only if all writes were successful
        event->buf_off += len + 9;
        event->context.argnum++;
        return 1;
    }

    return 0;
}

// INTERNAL: PERF BUFFER ---------------------------------------------------------------------------

static __always_inline int events_perf_submit(program_data_t *p, u32 id, long ret)
{
    p->event->context.eventid = id;
    p->event->context.retval = ret;

    // Get Stack trace
    if (p->config->options & OPT_CAPTURE_STACK_TRACES) {
        int stack_id = bpf_get_stackid(p->ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            p->event->context.stack_id = stack_id;
        }
    }

    u32 size = sizeof(event_context_t) + p->event->buf_off;

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_EVENT_SIZE));

    return bpf_perf_event_output(p->ctx, &events, BPF_F_CURRENT_CPU, p->event, size);
}

// INTERNAL: STRINGS -------------------------------------------------------------------------------

// Workaround: Newer LLVM versions might fail to optimize has_prefix()
// loop unrolling with the following error:
//
//     warning: loop not unrolled: the optimizer was unable to perform
//     the requested transformation; the transformation might be
//     disabled or specified as part of an unsupported transformation
//     ordering
//

#if defined(__clang__) && __clang_major__ > 13

    #define has_prefix(p, s, n)                                                                    \
        ({                                                                                         \
            int rc = 0;                                                                            \
            char *pre = p, *str = s;                                                               \
            _Pragma("unroll") for (int z = 0; z < n; pre++, str++, z++)                            \
            {                                                                                      \
                if (!*pre) {                                                                       \
                    rc = 1;                                                                        \
                    break;                                                                         \
                } else if (*pre != *str) {                                                         \
                    rc = 0;                                                                        \
                    break;                                                                         \
                }                                                                                  \
            }                                                                                      \
            rc;                                                                                    \
        })

#else

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

#endif

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

static __always_inline int save_args_to_submit_buf(event_data_t *event, u64 types, args_t *args)
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
            case U8_T:
                size = sizeof(u8);
                break;
            case U16_T:
                size = sizeof(u16);
                break;
            case STR_T:
                rc = save_str_to_buf(event, (void *) args->args[i], index);
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
                    rc = save_to_submit_buf(event, (void *) (args->args[i]), size, index);
                } else {
                    rc = save_to_submit_buf(event, &family, sizeof(short), index);
                }
                break;
            case INT_ARR_2_T:
                size = sizeof(int[2]);
                rc = save_to_submit_buf(event, (void *) (args->args[i]), size, index);
                break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T) && (type != INT_ARR_2_T)) {
            rc = save_to_submit_buf(event, (void *) &(args->args[i]), size, index);
        }

        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

// INTERNAL: SYSCALLS ------------------------------------------------------------------------------

static __always_inline bool has_syscall_fd_arg(uint syscall_id)
{
    // Only syscalls with one fd argument so far
    switch (syscall_id) {
        case SYSCALL_READ:
        case SYSCALL_WRITE:
        case SYSCALL_CLOSE:
        case SYSCALL_FSTAT:
        case SYSCALL_LSEEK:
        case SYSCALL_MMAP:
        case SYSCALL_IOCTL:
        case SYSCALL_PREAD64:
        case SYSCALL_PWRITE64:
        case SYSCALL_READV:
        case SYSCALL_WRITEV:
        case SYSCALL_DUP:
        case SYSCALL_CONNECT:
        case SYSCALL_ACCEPT:
        case SYSCALL_SENDTO:
        case SYSCALL_RECVFROM:
        case SYSCALL_SENDMSG:
        case SYSCALL_RECVMSG:
        case SYSCALL_SHUTDOWN:
        case SYSCALL_BIND:
        case SYSCALL_LISTEN:
        case SYSCALL_GETSOCKNAME:
        case SYSCALL_GETPEERNAME:
        case SYSCALL_SETSOCKOPT:
        case SYSCALL_GETSOCKOPT:
        case SYSCALL_FCNTL:
        case SYSCALL_FLOCK:
        case SYSCALL_FSYNC:
        case SYSCALL_FDATASYNC:
        case SYSCALL_FTRUNCATE:
        case SYSCALL_FCHDIR:
        case SYSCALL_FCHMOD:
        case SYSCALL_FCHOWN:
        case SYSCALL_FSTATFS:
        case SYSCALL_READAHEAD:
        case SYSCALL_FSETXATTR:
        case SYSCALL_FGETXATTR:
        case SYSCALL_FLISTXATTR:
        case SYSCALL_FREMOVEXATTR:
        case SYSCALL_GETDENTS64:
        case SYSCALL_FADVISE64:
        case SYSCALL_INOTIFY_ADD_WATCH:
        case SYSCALL_INOTIFY_RM_WATCH:
        case SYSCALL_OPENAT:
        case SYSCALL_MKDIRAT:
        case SYSCALL_MKNODAT:
        case SYSCALL_FCHOWNAT:
        case SYSCALL_UNLINKAT:
        case SYSCALL_SYMLINKAT:
        case SYSCALL_READLINKAT:
        case SYSCALL_FCHMODAT:
        case SYSCALL_FACCESSAT:
        case SYSCALL_SYNC_FILE_RANGE:
        case SYSCALL_VMSPLICE:
        case SYSCALL_UTIMENSAT:
        case SYSCALL_FALLOCATE:
        case SYSCALL_TIMERFD_SETTIME:
        case SYSCALL_TIMERFD_GETTIME:
        case SYSCALL_ACCEPT4:
        case SYSCALL_SIGNALFD4:
        case SYSCALL_PREADV:
        case SYSCALL_PWRITEV:
        case SYSCALL_PERF_EVENT_OPEN:
        case SYSCALL_RECVMMSG:
        case SYSCALL_NAME_TO_HANDLE_AT:
        case SYSCALL_OPEN_BY_HANDLE_AT:
        case SYSCALL_SYNCFS:
        case SYSCALL_SENDMMSG:
        case SYSCALL_SETNS:
        case SYSCALL_FINIT_MODULE:
        case SYSCALL_EXECVEAT:
        case SYSCALL_PREADV2:
        case SYSCALL_PWRITEV2:
        case SYSCALL_STATX:
        case SYSCALL_PIDFD_SEND_SIGNAL:
        case SYSCALL_IO_URING_ENTER:
        case SYSCALL_IO_URING_REGISTER:
        case SYSCALL_OPEN_TREE:
        case SYSCALL_FSCONFIG:
        case SYSCALL_FSMOUNT:
        case SYSCALL_FSPICK:
        case SYSCALL_OPENAT2:
        case SYSCALL_FACCESSAT2:
        case SYSCALL_PROCESS_MADVISE:
        case SYSCALL_EPOLL_PWAIT2:
        case SYSCALL_MOUNT_SETATTR:
        case SYSCALL_QUOTACTL_FD:
        case SYSCALL_LANDLOCK_ADD_RULE:
        case SYSCALL_LANDLOCK_RESTRICT_SELF:
        case SYSCALL_PROCESS_MRELEASE:
#if !defined(bpf_target_arm64)
        case SYSCALL_GETDENTS:
        case SYSCALL_EPOLL_WAIT:
        case SYSCALL_FUTIMESAT:
        case SYSCALL_NEWFSTATAT:
        case SYSCALL_EPOLL_PWAIT:
        case SYSCALL_SIGNALFD:
#endif
            return true;
    }

    return false;
}

static __always_inline uint get_syscall_fd_num_from_arg(uint syscall_id, args_t *args)
{
    switch (syscall_id) {
        case SYSCALL_SYMLINKAT:
            return args->args[1];
        case SYSCALL_PERF_EVENT_OPEN:
            return args->args[3];
        case SYSCALL_MMAP:
            return args->args[4];
    }

    return args->args[0];
}

// GENERIC PROBE MACROS ----------------------------------------------------------------------------

#define TRACE_ENT_FUNC(name, id)                                                                   \
    int trace_##name(struct pt_regs *ctx)                                                          \
    {                                                                                              \
        program_data_t p = {};                                                                     \
        if (!init_program_data(&p, ctx))                                                           \
            return 0;                                                                              \
                                                                                                   \
        if (!should_trace(&p))                                                                     \
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
        program_data_t p = {};                                                                     \
        if (!init_program_data(&p, ctx))                                                           \
            return 0;                                                                              \
                                                                                                   \
        if (!should_submit(id, &(p.event->context)))                                               \
            return 0;                                                                              \
                                                                                                   \
        save_args_to_submit_buf(p->event, types, &args);                                           \
                                                                                                   \
        return events_perf_submit(&p, id, ret);                                                    \
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

static __always_inline int save_sockaddr_to_buf(event_data_t *event, struct socket *sock, u8 index)
{
    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(event, (void *) &local, sizeof(struct sockaddr_in), index);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(event, (void *) &local, sizeof(struct sockaddr_in6), index);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(event, (void *) &sockaddr, sizeof(struct sockaddr_un), index);
    }
    return 0;
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

// HELPERS: SUBMIT SPECIFIC EVENT ------------------------------------------------------------------

// Used macro because of problem with verifier in NONCORE kinetic519
#define submit_mem_prot_alert_event(event, alert, addr, len, prot, previous_prot, file_info)       \
    {                                                                                              \
        save_to_submit_buf(event, &alert, sizeof(u32), 0);                                         \
        save_to_submit_buf(event, &addr, sizeof(void *), 1);                                       \
        save_to_submit_buf(event, &len, sizeof(size_t), 2);                                        \
        save_to_submit_buf(event, &prot, sizeof(int), 3);                                          \
        save_to_submit_buf(event, &previous_prot, sizeof(int), 4);                                 \
        if (file_info.pathname_p != NULL) {                                                        \
            save_str_to_buf(event, file_info.pathname_p, 5);                                       \
            save_to_submit_buf(event, &file_info.device, sizeof(dev_t), 6);                        \
            save_to_submit_buf(event, &file_info.inode, sizeof(unsigned long), 7);                 \
            save_to_submit_buf(event, &file_info.ctime, sizeof(u64), 8);                           \
        }                                                                                          \
        events_perf_submit(&p, MEM_PROT_ALERT, 0);                                                 \
    }

// SYSCALL HOOKS -----------------------------------------------------------------------------------

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
// initial entry for sys_enter syscall logic
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    int id = ctx->args[1];
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    bpf_tail_call(ctx, &sys_enter_init_tail, id);
    return 0;
}

// initial tail call entry from sys_enter.
// purpose is to save the syscall info of relevant syscalls through the task_info map.
// can move to one of:
// 1. sys_enter_submit, general event submit logic from sys_enter
// 2. directly to syscall tail hanler in sys_enter_tails
SEC("raw_tracepoint/sys_enter_init")
int sys_enter_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        u32 pid = pid_tgid >> 32;
        task_info = init_task_info(tid, pid, NULL);
        if (unlikely(task_info == NULL)) {
            return 0;
        }
    }

    syscall_data_t *sys = &(task_info->syscall_data);
    sys->id = ctx->args[1];

    if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)) {
        struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

        if (is_x86_compat(task)) {
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

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys->id);
        if (id_64 == 0)
            return 0;

        sys->id = *id_64;
    }

    // exit, exit_group and rt_sigreturn syscalls don't return
    if (sys->id != SYSCALL_EXIT && sys->id != SYSCALL_EXIT_GROUP &&
        sys->id != SYSCALL_RT_SIGRETURN) {
        sys->ts = bpf_ktime_get_ns();
        task_info->syscall_traced = true;
    }

    // if id is irrelevant continue to next tail call
    bpf_tail_call(ctx, &sys_enter_submit_tail, sys->id);

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// submit tail call part of sys_enter.
// events that are required for submission go through two logics here:
// 1. parsing their FD filepath if requested as an option
// 2. submitting the event if relevant
// may move to the direct syscall handler in sys_enter_tails
SEC("raw_tracepoint/sys_enter_submit")
int sys_enter_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (p.config->options & OPT_TRANSLATE_FD_FILEPATH && has_syscall_fd_arg(sys->id)) {
        // Process filepath related to fd argument
        uint fd_num = get_syscall_fd_num_from_arg(sys->id, &sys->args);
        struct file *file = get_struct_file_from_fd(fd_num);

        if (file) {
            fd_arg_task_t fd_arg_task = {
                .pid = p.event->context.task.pid,
                .tid = p.event->context.task.tid,
                .fd = fd_num,
            };

            fd_arg_path_t fd_arg_path = {};
            void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

            bpf_probe_read_str(&fd_arg_path.path, sizeof(fd_arg_path.path), file_path);
            bpf_map_update_elem(&fd_arg_path_map, &fd_arg_task, &fd_arg_path, BPF_ANY);
        }
    }
    if (sys->id != SYSCALL_RT_SIGRETURN && !p.task_info->syscall_traced) {
        save_to_submit_buf(p.event, (void *) &(sys->args.args[0]), sizeof(int), 0);
        events_perf_submit(&p, sys->id, 0);
    }

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long ret)
// initial entry for sys_exit syscall logic
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    bpf_tail_call(ctx, &sys_exit_init_tail, id);
    return 0;
}

// initial tail call entry from sys_exit.
// purpose is to "confirm" the syscall data saved by marking it as complete(see
// task_info->syscall_traced) and adding the return value to the syscall_info struct. can move to
// one of:
// 1. sys_exit, general event submit logic from sys_exit
// 2. directly to syscall tail hanler in sys_exit_tails
SEC("raw_tracepoint/sys_exit_init")
int sys_exit_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        u32 pid = pid_tgid >> 32;
        task_info = init_task_info(tid, pid, NULL);
        if (unlikely(task_info == NULL)) {
            return 0;
        }
    }

    // check if syscall is being traced and mark that it finished
    if (!task_info->syscall_traced)
        return 0;
    task_info->syscall_traced = false;

    syscall_data_t *sys = &task_info->syscall_data;

    long ret = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // Sanity check - we returned from the expected syscall this task was executing
    if (sys->id != id)
        return 0;

    sys->ret = ret;

    // move to submit tail call if needed
    bpf_tail_call(ctx, &sys_exit_submit_tail, id);

    // otherwise move to direct syscall handler
    bpf_tail_call(ctx, &sys_exit_tails, id);
    return 0;
}

// submit tail call part of sys_exit.
// most syscall events are submitted at this point, and if not,
// they are submitted through direct syscall handlers in sys_exit_tails
SEC("raw_tracepoint/sys_exit_submit")
int sys_exit_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    uint id = sys->id;
    long ret = ctx->args[1];

    if ((id != SYSCALL_EXECVE && id != SYSCALL_EXECVEAT) ||
        ((id == SYSCALL_EXECVE || id == SYSCALL_EXECVEAT) && (ret != 0))) {
        // We can't use saved args after execve syscall, as pointers are
        // invalid To avoid showing execve event both on entry and exit, we
        // only output failed execs
        if (!should_submit(id, &(p.event->context)))
            return 0;
        u64 types = 0;
        u64 *saved_types = bpf_map_lookup_elem(&params_types_map, &id);
        if (!saved_types) {
            bpf_tail_call(ctx, &sys_exit_tails, id);
            return 0;
        }
        types = *saved_types;
        save_args_to_submit_buf(p.event, types, &sys->args);
        p.event->context.ts = sys->ts;
        events_perf_submit(&p, id, ret);
    }

    bpf_tail_call(ctx, &sys_exit_tails, id);
    return 0;
}

// here are the direct hook points for sys_enter and sys_exit.
// There are used not for submitting syscall events but the enter and exit events themselves.
// As such they are usually not attached, and will only be used if sys_enter or sys_exit events are
// given as tracing arguments.

// separate hook point for sys_enter event tracing
SEC("raw_tracepoint/trace_sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(RAW_SYS_ENTER, &(p.event->context)))
        return 0;

    // always submit since this won't be attached otherwise
    int id = ctx->args[1];
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 0);
    events_perf_submit(&p, RAW_SYS_ENTER, 0);
    return 0;
}

// separate hook point for sys_exit event tracing
SEC("raw_tracepoint/trace_sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(RAW_SYS_EXIT, &(p.event->context)))
        return 0;

    // always submit since this won't be attached otherwise
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 0);
    events_perf_submit(&p, RAW_SYS_EXIT, 0);
    return 0;
}

// PROBES AND HELPERS ------------------------------------------------------------------------------

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;

    if (!should_submit(SYSCALL_EXECVE, &(p.event->context)))
        return 0;

    save_str_to_buf(p.event, (void *) sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[1] /*argv*/, 1);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[2] /*envp*/, 2);
    }

    return events_perf_submit(&p, SYSCALL_EXECVE, 0);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;

    if (!should_submit(SYSCALL_EXECVEAT, &(p.event->context)))
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(p.event, (void *) sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[2] /*argv*/, 2);
    if (p.config->options & OPT_EXEC_ENV) {
        save_str_arr_to_buf(p.event, (const char *const *) sys->args.args[3] /*envp*/, 3);
    }
    save_to_submit_buf(p.event, (void *) &sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_perf_submit(&p, SYSCALL_EXECVEAT, 0);
}

static __always_inline int send_socket_dup(program_data_t *p, u64 oldfd, u64 newfd)
{
    if (!should_submit(SOCKET_DUP, &(p->event->context)))
        return 0;

    if (!check_fd_type(oldfd, S_IFSOCK)) {
        return 0;
    }

    struct file *f = get_struct_file_from_fd(oldfd);
    if (f == NULL) {
        return -1;
    }

    // this is a socket - submit the SOCKET_DUP event

    save_to_submit_buf(p->event, &oldfd, sizeof(u32), 0);
    save_to_submit_buf(p->event, &newfd, sizeof(u32), 1);

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

        save_to_submit_buf(p->event, &remote, sizeof(struct sockaddr_in), 2);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 remote;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);

        save_to_submit_buf(p->event, &remote, sizeof(struct sockaddr_in6), 2);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);

        save_to_submit_buf(p->event, &sockaddr, sizeof(struct sockaddr_un), 2);
    }

    return events_perf_submit(p, SOCKET_DUP, 0);
}

SEC("raw_tracepoint/sys_dup")
int sys_dup_exit_tail(void *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (sys->ret < 0) {
        // dup failed
        return 0;
    }

    if (sys->id == SYSCALL_DUP) {
        // args.args[0]: oldfd
        // retval: newfd
        send_socket_dup(&p, sys->args.args[0], sys->ret);
    } else if (sys->id == SYSCALL_DUP2 || sys->id == SYSCALL_DUP3) {
        // args.args[0]: oldfd
        // args.args[1]: newfd
        // retval: retval
        send_socket_dup(&p, sys->args.args[0], sys->args.args[1]);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *parent, struct task_struct *child)
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Note: we don't place should_trace() here, so we can keep track of the cgroups in the system
    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    u64 start_time = get_task_start_time(child);

    task_info_t task = {};
    __builtin_memcpy(&task, p.task_info, sizeof(task_info_t));
    task.recompute_scope = true;
    task.context.tid = get_task_ns_pid(child);
    task.context.host_tid = get_task_host_pid(child);
    task.context.start_time = start_time;
    ret = bpf_map_update_elem(&task_info_map, &task.context.host_tid, &task, BPF_ANY);
    if (ret < 0)
        tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);

    int parent_pid = get_task_host_pid(parent);
    int child_pid = get_task_host_pid(child);

    int parent_tgid = get_task_host_tgid(parent);
    int child_tgid = get_task_host_tgid(child);

    proc_info_t *c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_tgid);
    if (c_proc_info == NULL) {
        // this is a new process (and not just another thread) - add it to proc_info_map

        proc_info_t *p_proc_info = bpf_map_lookup_elem(&proc_info_map, &parent_tgid);
        if (unlikely(p_proc_info == NULL)) {
            // parent proc should exist in proc_map (init_program_data should have set it)
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        bpf_map_update_elem(&proc_info_map, &child_tgid, p_proc_info, BPF_NOEXIST);
        c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_tgid);
        // appease the verifier
        if (unlikely(c_proc_info == NULL)) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        c_proc_info->follow_in_scopes = 0;
        c_proc_info->new_proc = true;
    }

    // update process tree map if the parent has an entry
    if (p.config->proc_tree_filter_enabled_scopes) {
        u32 *tgid_filtered = bpf_map_lookup_elem(&process_tree_map, &parent_tgid);
        if (tgid_filtered) {
            ret = bpf_map_update_elem(&process_tree_map, &child_tgid, tgid_filtered, BPF_ANY);
            if (ret < 0)
                tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);
        }
    }

    if (!should_trace(&p))
        return 0;

    // follow every pid that passed the should_trace() checks (used by the follow filter)
    c_proc_info->follow_in_scopes = p.task_info->matched_scopes;

    if (should_submit(SCHED_PROCESS_FORK, &(p.event->context)) ||
        p.config->options & OPT_PROCESS_INFO) {
        int parent_ns_pid = get_task_ns_pid(parent);
        int parent_ns_tgid = get_task_ns_tgid(parent);
        int child_ns_pid = get_task_ns_pid(child);
        int child_ns_tgid = get_task_ns_tgid(child);

        save_to_submit_buf(p.event, (void *) &parent_pid, sizeof(int), 0);
        save_to_submit_buf(p.event, (void *) &parent_ns_pid, sizeof(int), 1);
        save_to_submit_buf(p.event, (void *) &parent_tgid, sizeof(int), 2);
        save_to_submit_buf(p.event, (void *) &parent_ns_tgid, sizeof(int), 3);
        save_to_submit_buf(p.event, (void *) &child_pid, sizeof(int), 4);
        save_to_submit_buf(p.event, (void *) &child_ns_pid, sizeof(int), 5);
        save_to_submit_buf(p.event, (void *) &child_tgid, sizeof(int), 6);
        save_to_submit_buf(p.event, (void *) &child_ns_tgid, sizeof(int), 7);
        save_to_submit_buf(p.event, (void *) &start_time, sizeof(u64), 8);

        events_perf_submit(&p, SCHED_PROCESS_FORK, 0);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // Perform the following checks before should_trace() so we can filter by newly created
    // containers/processes.  We assume that a new container/pod has started when a process of a
    // newly created cgroup and mount ns executed a binary
    if (p.task_info->container_state == CONTAINER_CREATED) {
        u32 mntns = get_task_mnt_ns_id(p.event->task);
        struct task_struct *parent = get_parent_task(p.event->task);
        u32 parent_mntns = get_task_mnt_ns_id(parent);
        if (mntns != parent_mntns) {
            u32 cgroup_id_lsb = p.event->context.task.cgroup_id;
            u8 state = CONTAINER_STARTED;
            bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
            p.task_info->container_state = state;
            p.event->context.task.flags |= CONTAINER_STARTED_FLAG; // Change for current event
            p.task_info->context.flags |= CONTAINER_STARTED_FLAG;  // Change for future task events
        }
    }

    p.task_info->recompute_scope = true;

    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    if (bprm == NULL) {
        return -1;
    }
    struct file *file = get_file_ptr_from_bprm(bprm);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &p.event->context.task.host_pid);
    if (proc_info == NULL) {
        // entry should exist in proc_map (init_program_data should have set it otherwise)
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    proc_info->new_proc = true;

    // extract the binary name to be used in should_trace
    __builtin_memset(proc_info->binary.path, 0, MAX_BIN_PATH_SIZE);
    bpf_probe_read_str(proc_info->binary.path, MAX_BIN_PATH_SIZE, file_path);
    proc_info->binary.mnt_id = p.event->context.task.mnt_id;

    if (!should_trace(&p))
        return 0;

    // Follow this task for matched scopes
    proc_info->follow_in_scopes = p.task_info->matched_scopes;

    if (!should_submit(SCHED_PROCESS_EXEC, &(p.event->context)) &&
        (p.config->options & OPT_PROCESS_INFO) != OPT_PROCESS_INFO)
        return 0;

    // Note: Starting from kernel 5.9, there are two new interesting fields in bprm that we
    // should consider adding:
    // 1. struct file *executable - can be used to get the executable name passed to an
    // interpreter
    // 2. fdpath                  - generated filename for execveat (after resolving dirfd)
    const char *filename = get_binprm_filename(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    u64 ctime = get_ctime_nanosec_from_file(file);
    umode_t inode_mode = get_inode_mode_from_file(file);

    save_str_to_buf(p.event, (void *) filename, 0);
    save_str_to_buf(p.event, file_path, 1);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);
    save_to_submit_buf(p.event, &inode_mode, sizeof(umode_t), 5);
    // If the interpreter file is the same as the executed one, it means that there is no
    // interpreter. For more information, see the load_elf_phdrs kprobe program.
    if (proc_info->interpreter.inode != 0 &&
        (proc_info->interpreter.device != s_dev || proc_info->interpreter.inode != inode_nr)) {
        save_str_to_buf(p.event, &proc_info->interpreter.pathname, 6);
        save_to_submit_buf(p.event, &proc_info->interpreter.device, sizeof(dev_t), 7);
        save_to_submit_buf(p.event, &proc_info->interpreter.inode, sizeof(unsigned long), 8);
        save_to_submit_buf(p.event, &proc_info->interpreter.ctime, sizeof(u64), 9);
    }

    bpf_tail_call(ctx, &prog_array_tp, TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT);
    return -1;
}

SEC("raw_tracepoint/sched_process_exec_event_submit_tail")
int sched_process_exec_event_submit_tail(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];

    if (bprm == NULL)
        return -1;

    // bprm->mm is null at this point (set by begin_new_exec()), and task->mm is already initialized
    struct mm_struct *mm = get_mm_from_task(task);

    unsigned long arg_start, arg_end;
    arg_start = get_arg_start_from_mm(mm);
    arg_end = get_arg_end_from_mm(mm);
    int argc = get_argc_from_bprm(bprm);

    struct file *stdin_file = get_struct_file_from_fd(0);
    unsigned short stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
    void *stdin_path = get_path_str(GET_FIELD_ADDR(stdin_file->f_path));
    const char *interp = get_binprm_interp(bprm);

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD) {
        invoked_from_kernel = 1;
    }
    save_args_str_arr_to_buf(p.event, (void *) arg_start, (void *) arg_end, argc, 10);
    save_str_to_buf(p.event, (void *) interp, 11);
    save_to_submit_buf(p.event, &stdin_type, sizeof(unsigned short), 12);
    save_str_to_buf(p.event, stdin_path, 13);
    save_to_submit_buf(p.event, &invoked_from_kernel, sizeof(int), 14);
    if (p.config->options & OPT_EXEC_ENV) {
        unsigned long env_start, env_end;
        env_start = get_env_start_from_mm(mm);
        env_end = get_env_end_from_mm(mm);
        int envc = get_envc_from_bprm(bprm);

        save_args_str_arr_to_buf(p.event, (void *) env_start, (void *) env_end, envc, 15);
    }

    events_perf_submit(&p, SCHED_PROCESS_EXEC, 0);
    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // evaluate should_trace before removing this pid from the maps
    bool traced = !!should_trace(&p);

    bpf_map_delete_elem(&task_info_map, &p.event->context.task.host_tid);

    bool group_dead = false;
    struct task_struct *task = p.event->task;
    struct signal_struct *signal = READ_KERN(task->signal);
    atomic_t live = READ_KERN(signal->live);
    // This check could be true for multiple thread exits if the thread count was 0 when the hooks
    // were triggered. This could happen for example if the threads performed exit in different CPUs
    // simultaneously.
    if (live.counter == 0) {
        group_dead = true;
    }

    if (!traced)
        return 0;

    long exit_code = get_task_exit_code(p.event->task);

    if (should_submit(SCHED_PROCESS_EXIT, &(p.event->context)) ||
        p.config->options & OPT_PROCESS_INFO) {
        save_to_submit_buf(p.event, (void *) &exit_code, sizeof(long), 0);
        save_to_submit_buf(p.event, (void *) &group_dead, sizeof(bool), 1);

        events_perf_submit(&p, SCHED_PROCESS_EXIT, 0);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_free")
int tracepoint__sched__sched_process_free(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) ctx->args[0];

    int pid = get_task_host_pid(task);
    int tgid = get_task_host_tgid(task);

    if (pid == tgid) {
        // we only care about process (and not thread) exit
        // if tgid task is freed, we know for sure that the process exited
        // so we can safely remove it from the process map
        bpf_map_delete_elem(&proc_info_map, &tgid);
        bpf_map_delete_elem(&process_tree_map, &tgid);
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
    del_args(SOCKET_ACCEPT);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    struct socket *old_sock = (struct socket *) saved_args.args[0];
    struct socket *new_sock = (struct socket *) saved_args.args[1];

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

        save_to_submit_buf(p.event, (void *) &local, sizeof(struct sockaddr_in), 1);

        net_conn_v4_t net_details_new = {};
        struct sockaddr_in remote;
        get_network_details_from_sock_v4(sk_new, &net_details_new, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details_new, family_new);

        save_to_submit_buf(p.event, (void *) &remote, sizeof(struct sockaddr_in), 2);
    } else if (family_old == AF_INET6 && family_new == AF_INET6) {
        net_conn_v6_t net_details_old = {};
        struct sockaddr_in6 local;
        get_network_details_from_sock_v6(sk_old, &net_details_old, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details_old, family_old);

        save_to_submit_buf(p.event, (void *) &local, sizeof(struct sockaddr_in6), 1);

        net_conn_v6_t net_details_new = {};

        struct sockaddr_in6 remote;
        get_network_details_from_sock_v6(sk_new, &net_details_new, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details_new, family_new);

        save_to_submit_buf(p.event, (void *) &remote, sizeof(struct sockaddr_in6), 2);
    } else if (family_old == AF_UNIX && family_new == AF_UNIX) {
        struct unix_sock *unix_sk_new = (struct unix_sock *) sk_new;
        struct sockaddr_un sockaddr_new = get_unix_sock_addr(unix_sk_new);
        save_to_submit_buf(p.event, (void *) &sockaddr_new, sizeof(struct sockaddr_un), 1);
    } else {
        return 0;
    }
    return events_perf_submit(&p, SOCKET_ACCEPT, 0);
}

// trace/events/sched.h: TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SCHED_SWITCH, &(p.event->context)))
        return 0;

    struct task_struct *prev = (struct task_struct *) ctx->args[1];
    struct task_struct *next = (struct task_struct *) ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(p.event, (void *) &cpu, sizeof(int), 0);
    save_to_submit_buf(p.event, (void *) &prev_pid, sizeof(int), 1);
    save_str_to_buf(p.event, prev->comm, 2);
    save_to_submit_buf(p.event, (void *) &next_pid, sizeof(int), 3);
    save_str_to_buf(p.event, next->comm, 4);

    return events_perf_submit(&p, SCHED_SWITCH, 0);
}

SEC("kprobe/filldir64")
int BPF_KPROBE(trace_filldir64)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(HIDDEN_INODES, &(p.event->context)))
        return 0;

    char *process_name = (char *) PT_REGS_PARM2(ctx);
    unsigned long process_inode_number = (unsigned long) PT_REGS_PARM5(ctx);
    if (process_inode_number == 0) {
        save_str_to_buf(p.event, process_name, 0);
        return events_perf_submit(&p, HIDDEN_INODES, 0);
    }
    return 0;
}

SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(trace_call_usermodehelper)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CALL_USERMODE_HELPER, &(p.event->context)))
        return 0;

    void *path = (void *) PT_REGS_PARM1(ctx);
    unsigned long argv = PT_REGS_PARM2(ctx);
    unsigned long envp = PT_REGS_PARM3(ctx);
    int wait = PT_REGS_PARM4(ctx);

    save_str_to_buf(p.event, path, 0);
    save_str_arr_to_buf(p.event, (const char *const *) argv, 1);
    save_str_arr_to_buf(p.event, (const char *const *) envp, 2);
    save_to_submit_buf(p.event, (void *) &wait, sizeof(int), 3);

    return events_perf_submit(&p, CALL_USERMODE_HELPER, 0);
}

SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DO_EXIT, &(p.event->context)))
        return 0;

    long code = PT_REGS_PARM1(ctx);

    return events_perf_submit(&p, DO_EXIT, code);
}

// uprobe_syscall_trigger submit to the buff the syscalls function handlers
// address from the syscall table. the syscalls are stored in map which is
// syscalls_to_check_map and the syscall-table address is stored in the
// kernel_symbols map.

SEC("uprobe/trigger_syscall_event")
int uprobe_syscall_trigger(struct pt_regs *ctx)
{
    u64 caller_ctx_id = 0;
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;

    // clang-format off
    //
    // Golang calling convention is being changed from a stack based argument
    // passing (plan9 like) to register based argument passing whenever
    // possible. In arm64, this change happened from go1.17 to go1.18. Use a
    // magic number argument to allow uprobe handler to recognize the calling
    // convention in a simple way.

    #if defined(bpf_target_x86)
        // go1.17, go1.18, go 1.19
        caller_ctx_id = ctx->cx;                                      // 2nd arg
    #elif defined(bpf_target_arm64)
        // go1.17
        u64 magic_num = 0;
        bpf_probe_read(&magic_num, 8, ((void *) ctx->sp) + 16);       // 1st arg
        bpf_probe_read(&caller_ctx_id, 8, ((void *) ctx->sp) + 24);   // 2nd arg
        if (magic_num != UPROBE_MAGIC_NUMBER) {
            // go1.18, go 1.19
            magic_num = ctx->user_regs.regs[1];                       // 1st arg
            caller_ctx_id = ctx->user_regs.regs[2];                   // 2nd arg
        }
    #else
        return 0;
    #endif
    // clang-format on

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    int key = 0;
    // TODO: https://github.com/aquasecurity/tracee/issues/2055
    if (bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &key) == NULL)
        return 0;

    char syscall_table_sym[15] = "sys_call_table";
    u64 *syscall_table_addr = (u64 *) get_symbol_addr(syscall_table_sym);
    if (unlikely(syscall_table_addr == 0))
        return 0;
    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    u64 idx;
    unsigned long syscall_addr = 0;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK];

#pragma unroll
    for (int i = 0; i < NUMBER_OF_SYSCALLS_TO_CHECK; i++) {
        idx = i;
        // syscalls_to_check_map format: [syscall#][syscall#][syscall#]
        u64 *syscall_num_p = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &idx);
        if (syscall_num_p == NULL) {
            syscall_address[i] = 0;
            continue;
        }

        syscall_addr = READ_KERN(syscall_table_addr[*syscall_num_p]);
        if (syscall_addr == 0) {
            return 0;
        }

        // skip if in text segment range
        if (syscall_addr >= (u64) stext_addr && syscall_addr < (u64) etext_addr) {
            syscall_address[i] = 0;
            continue;
        }

        syscall_address[i] = syscall_addr;
    }
    save_u64_arr_to_buf(p.event, (const u64 *) syscall_address, NUMBER_OF_SYSCALLS_TO_CHECK, 0);
    save_to_submit_buf(p.event, (void *) &caller_ctx_id, sizeof(uint64_t), 1);
    return events_perf_submit(&p, PRINT_SYSCALL_TABLE, 0);
}

SEC("uprobe/trigger_seq_ops_event")
int uprobe_seq_ops_trigger(struct pt_regs *ctx)
{
    u64 caller_ctx_id = 0;
    u64 *address_array = NULL;
    u64 struct_address;
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;

    // clang-format off
    //
    // Golang calling convention is being changed from a stack based argument
    // passing (plan9 like) to register based argument passing whenever
    // possible. In arm64, this change happened from go1.17 to go1.18. Use a
    // magic number argument to allow uprobe handler to recognize the calling
    // convention in a simple way.

    #if defined(bpf_target_x86)
        // go1.17, go1.18, go 1.19
        caller_ctx_id = ctx->cx;                                      // 2nd arg
        address_array = ((void *) ctx->sp + 8);                       // 3rd arg
    #elif defined(bpf_target_arm64)
        // go1.17
        u64 magic_num = 0;
        bpf_probe_read(&magic_num, 8, ((void *) ctx->sp) + 16);       // 1st arg
        bpf_probe_read(&caller_ctx_id, 8, ((void *) ctx->sp) + 24);   // 2nd arg
        address_array = ((void *) ctx->sp + 32);                      // 3rd arg
        if (magic_num != UPROBE_MAGIC_NUMBER) {
            // go1.18 and go1.19
            magic_num = ctx->user_regs.regs[1];                       // 1st arg
            caller_ctx_id = ctx->user_regs.regs[2];                   // 2nd arg
            address_array = ((void *) ctx->sp + 8);                   // 3rd arg
        }
    #else
        return 0;
    #endif
    // clang-format on

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    u32 count_off = p.event->buf_off + 1;
    save_u64_arr_to_buf(p.event, NULL, 0, 0); // init u64 array with size 0

#pragma unroll
    for (int i = 0; i < NET_SEQ_OPS_TYPES; i++) {
        bpf_probe_read(&struct_address, 8, (address_array + i));
        struct seq_operations *seq_ops = (struct seq_operations *) struct_address;

        u64 show_addr = (u64) READ_KERN(seq_ops->show);
        if (show_addr == 0)
            return 0;
        if (show_addr >= (u64) stext_addr && show_addr < (u64) etext_addr)
            show_addr = 0;

        u64 start_addr = (u64) READ_KERN(seq_ops->start);
        if (start_addr == 0)
            return 0;
        if (start_addr >= (u64) stext_addr && start_addr < (u64) etext_addr)
            start_addr = 0;

        u64 next_addr = (u64) READ_KERN(seq_ops->next);
        if (next_addr == 0)
            return 0;
        if (next_addr >= (u64) stext_addr && next_addr < (u64) etext_addr)
            next_addr = 0;

        u64 stop_addr = (u64) READ_KERN(seq_ops->stop);
        if (stop_addr == 0)
            return 0;
        if (stop_addr >= (u64) stext_addr && stop_addr < (u64) etext_addr)
            stop_addr = 0;

        u64 seq_ops_addresses[NET_SEQ_OPS_SIZE + 1] = {show_addr, start_addr, next_addr, stop_addr};

        add_u64_elements_to_buf(p.event, (const u64 *) seq_ops_addresses, 4, count_off);
    }

    save_to_submit_buf(p.event, (void *) &caller_ctx_id, sizeof(uint64_t), 1);
    events_perf_submit(&p, PRINT_NET_SEQ_OPS, 0);
    return 0;
}

SEC("uprobe/trigger_mem_dump_event")
int uprobe_mem_dump_trigger(struct pt_regs *ctx)
{
    u64 address = 0;
    u64 size = 0;
    u64 caller_ctx_id = 0;
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;

#if defined(bpf_target_x86)
    address = ctx->bx;       // 1st arg
    size = ctx->cx;          // 2nd arg
    caller_ctx_id = ctx->di; // 3rd arg
#elif defined(bpf_target_arm64)
    address = ctx->user_regs.regs[1];       // 1st arg
    size = ctx->user_regs.regs[2];          // 2nd arg
    caller_ctx_id = ctx->user_regs.regs[3]; // 3rd arg
#else
    return 0;
#endif

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // uprobe was triggered from other tracee instance
    if (p.config->tracee_pid != trigger_pid)
        return 0;

    if (size <= 0)
        return 0;

    int ret = save_bytes_to_buf(p.event, (void *) address, size & MAX_MEM_DUMP_SIZE, 0);
    // return in case of failed pointer read
    if (ret == 0) {
        tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_MEM_READ, ret);
        return 0;
    }
    save_to_submit_buf(p.event, (void *) &address, sizeof(void *), 1);
    save_to_submit_buf(p.event, &size, sizeof(u64), 2);
    save_to_submit_buf(p.event, &caller_ctx_id, sizeof(u64), 3);

    return events_perf_submit(&p, PRINT_MEM_DUMP, 0);
}

static __always_inline struct trace_kprobe *get_trace_kprobe_from_trace_probe(void *tracep)
{
    struct trace_kprobe *tracekp =
        (struct trace_kprobe *) container_of(tracep, struct trace_kprobe, tp);

    return tracekp;
}

static __always_inline struct trace_uprobe *get_trace_uprobe_from_trace_probe(void *tracep)
{
    struct trace_uprobe *traceup =
        (struct trace_uprobe *) container_of(tracep, struct trace_uprobe, tp);

    return traceup;
}

// This function returns a pointer to struct trace_probe from struct trace_event_call.
static __always_inline void *get_trace_probe_from_trace_event_call(struct trace_event_call *call)
{
    void *tracep_ptr;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0))
    tracep_ptr = container_of(call, struct trace_probe, call);
    #else
    struct trace_probe_event *tpe = container_of(call, struct trace_probe_event, call);
    struct list_head probes = READ_KERN(tpe->probes);
    tracep_ptr = container_of(probes.next, struct trace_probe, list);
    #endif
#else
    struct trace_probe___v53 *legacy_tracep;
    if (bpf_core_field_exists(legacy_tracep->call)) {
        tracep_ptr = container_of(call, struct trace_probe___v53, call);
    } else {
        struct trace_probe_event *tpe = container_of(call, struct trace_probe_event, call);
        struct list_head probes = READ_KERN(tpe->probes);
        tracep_ptr = container_of(probes.next, struct trace_probe, list);
    }
#endif

    return tracep_ptr;
}

// Inspired by bpf_get_perf_event_info() kernel func.
// https://elixir.bootlin.com/linux/v5.19.2/source/kernel/trace/bpf_trace.c#L2123
static __always_inline int
send_bpf_attach(program_data_t *p, struct file *bpf_prog_file, struct file *perf_event_file)
{
    if (!should_submit(BPF_ATTACH, &(p->event->context))) {
        return 0;
    }

// get real values of TRACE_EVENT_FL_KPROBE and TRACE_EVENT_FL_UPROBE.
// these values were changed in kernels >= 5.15.
#ifdef CORE
    int TRACE_EVENT_FL_KPROBE_BIT;
    int TRACE_EVENT_FL_UPROBE_BIT;
    if (bpf_core_field_exists(((struct trace_event_call *) 0)->module)) { // kernel >= 5.15
        TRACE_EVENT_FL_KPROBE_BIT = 6;
        TRACE_EVENT_FL_UPROBE_BIT = 7;
    } else { // kernel < 5.15
        TRACE_EVENT_FL_KPROBE_BIT = 5;
        TRACE_EVENT_FL_UPROBE_BIT = 6;
    }
    int TRACE_EVENT_FL_KPROBE = (1 << TRACE_EVENT_FL_KPROBE_BIT);
    int TRACE_EVENT_FL_UPROBE = (1 << TRACE_EVENT_FL_UPROBE_BIT);
#endif

    // get perf event details

// clang-format off
#define MAX_PERF_EVENT_NAME ((MAX_PATH_PREF_SIZE > MAX_KSYM_NAME_SIZE) ? \
    MAX_PATH_PREF_SIZE : MAX_KSYM_NAME_SIZE)
// clang-format on
#define REQUIRED_SYSTEM_LENGTH 9

    struct perf_event *event = (struct perf_event *) READ_KERN(perf_event_file->private_data);
    struct trace_event_call *tp_event = READ_KERN(event->tp_event);
    char event_name[MAX_PERF_EVENT_NAME];
    u64 probe_addr = 0;
    int perf_type;

    int flags = READ_KERN(tp_event->flags);

    // check if syscall_tracepoint
    bool is_syscall_tracepoint = false;
    struct trace_event_class *tp_class = READ_KERN(tp_event->class);
    char class_system[REQUIRED_SYSTEM_LENGTH];
    bpf_probe_read_str(&class_system, REQUIRED_SYSTEM_LENGTH, READ_KERN(tp_class->system));
    class_system[REQUIRED_SYSTEM_LENGTH - 1] = '\0';
    if (has_prefix("syscalls", class_system, REQUIRED_SYSTEM_LENGTH)) {
        is_syscall_tracepoint = true;
    }

    if (flags & TRACE_EVENT_FL_TRACEPOINT) { // event is tracepoint

        perf_type = PERF_TRACEPOINT;
        struct tracepoint *tp = READ_KERN(tp_event->tp);
        bpf_probe_read_str(&event_name, MAX_KSYM_NAME_SIZE, READ_KERN(tp->name));

    } else if (is_syscall_tracepoint) { // event is syscall tracepoint

        perf_type = PERF_TRACEPOINT;
        bpf_probe_read_str(&event_name, MAX_KSYM_NAME_SIZE, READ_KERN(tp_event->name));

    } else {
        bool is_ret_probe = false;
        void *tracep_ptr = get_trace_probe_from_trace_event_call(tp_event);

        if (flags & TRACE_EVENT_FL_KPROBE) { // event is kprobe

            struct trace_kprobe *tracekp = get_trace_kprobe_from_trace_probe(tracep_ptr);

            // check if probe is a kretprobe
            struct kretprobe *krp = &tracekp->rp;
            kretprobe_handler_t handler_f = READ_KERN(krp->handler);
            if (handler_f != NULL)
                is_ret_probe = true;

            if (is_ret_probe)
                perf_type = PERF_KRETPROBE;
            else
                perf_type = PERF_KPROBE;

            // get symbol name
            bpf_probe_read_str(&event_name, MAX_KSYM_NAME_SIZE, READ_KERN(tracekp->symbol));

            // get symbol address
            if (!event_name[0])
                probe_addr = (unsigned long) READ_KERN(krp->kp.addr);

        } else if (flags & TRACE_EVENT_FL_UPROBE) { // event is uprobe

            struct trace_uprobe *traceup = get_trace_uprobe_from_trace_probe(tracep_ptr);

            // determine if ret probe
            struct uprobe_consumer *upc = &traceup->consumer;
            void *handler_f = READ_KERN(upc->ret_handler);
            if (handler_f != NULL)
                is_ret_probe = true;

            if (is_ret_probe)
                perf_type = PERF_URETPROBE;
            else
                perf_type = PERF_UPROBE;

            // get binary path
            bpf_probe_read_str(&event_name, MAX_PATH_PREF_SIZE, READ_KERN(traceup->filename));

            // get symbol offset
            probe_addr = READ_KERN(traceup->offset);

        } else {
            // unsupported perf type
            return 0;
        }
    }

    // get bpf prog details

    struct bpf_prog *prog = (struct bpf_prog *) READ_KERN(bpf_prog_file->private_data);
    int prog_type = READ_KERN(prog->type);
    struct bpf_prog_aux *prog_aux = READ_KERN(prog->aux);
    u32 prog_id = READ_KERN(prog_aux->id);
    char prog_name[BPF_OBJ_NAME_LEN];
    bpf_probe_read_str(&prog_name, BPF_OBJ_NAME_LEN, READ_KERN(prog_aux->name));

    // get usage of helper bpf_probe_write_user
    bpf_attach_t *val = bpf_map_lookup_elem(&bpf_attach_map, &prog_id);
    if (val == NULL)
        return 0;

    // submit the event

    save_to_submit_buf(p->event, &prog_type, sizeof(int), 0);
    save_str_to_buf(p->event, (void *) &prog_name, 1);
    save_str_to_buf(p->event, (void *) &event_name, 2);
    save_to_submit_buf(p->event, &probe_addr, sizeof(u64), 3);
    save_to_submit_buf(p->event, &val->write_user, sizeof(int), 4);
    save_to_submit_buf(p->event, &perf_type, sizeof(int), 5);

    events_perf_submit(p, BPF_ATTACH, 0);

    // delete from map
    bpf_map_delete_elem(&bpf_attach_map, &prog_id);

    return 0;
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(trace_security_file_ioctl)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    unsigned int cmd = PT_REGS_PARM2(ctx);

    if (cmd == PERF_EVENT_IOC_SET_BPF) {
        struct file *perf_event_file = (struct file *) PT_REGS_PARM1(ctx);
        unsigned long fd = PT_REGS_PARM3(ctx);
        struct file *bpf_prog_file = get_struct_file_from_fd(fd);

        send_bpf_attach(&p, bpf_prog_file, perf_event_file);
    }

    return 0;
}

// trace/events/cgroup.h:
// TP_PROTO(struct cgroup *dst_cgrp, const char *path, struct task_struct *task, bool threadgroup)
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    char *path = (char *) ctx->args[1];
    struct task_struct *task = (struct task_struct *) ctx->args[2];

    int pid = get_task_host_pid(task);
    char *comm = READ_KERN(task->comm);

    save_str_to_buf(p.event, path, 0);
    save_str_to_buf(p.event, comm, 1);
    save_to_submit_buf(p.event, (void *) &pid, sizeof(int), 2);
    events_perf_submit(&p, CGROUP_ATTACH_TASK, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    p.event->context.matched_scopes = 0xFFFFFFFFFFFFFFFF; // see tracee.GetEssentialEvents

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((p.config->options & OPT_CGROUP_V1) && (p.config->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update) {
        // Assume this is a new container. If not, userspace code will delete this entry
        u8 state = CONTAINER_CREATED;
        bpf_map_update_elem(&containers_map, &cgroup_id_lsb, &state, BPF_ANY);
        p.task_info->container_state = state;
    }

    save_to_submit_buf(p.event, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(p.event, path, 1);
    save_to_submit_buf(p.event, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&p, CGROUP_MKDIR, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    p.event->context.matched_scopes = 0xFFFFFFFFFFFFFFFF; // see tracee.GetEssentialEvents

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    bool should_update = true;
    if ((p.config->options & OPT_CGROUP_V1) && (p.config->cgroup_v1_hid != hierarchy_id))
        should_update = false;

    if (should_update)
        bpf_map_delete_elem(&containers_map, &cgroup_id_lsb);

    save_to_submit_buf(p.event, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(p.event, path, 1);
    save_to_submit_buf(p.event, &hierarchy_id, sizeof(u32), 2);
    events_perf_submit(&p, CGROUP_RMDIR, 0);

    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_BPRM_CHECK, &(p.event->context)))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    struct file *file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 2);

    return events_perf_submit(&p, SECURITY_BPRM_CHECK, 0);
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_FILE_OPEN, &(p.event->context)))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    // Load the arguments given to the open syscall (which eventually invokes this function)
    char empty_string[1] = "";
    void *syscall_pathname = &empty_string;
    syscall_data_t *sys;
    bool syscall_traced = p.task_info->syscall_traced;
    if (syscall_traced) {
        sys = &p.task_info->syscall_data;
        switch (sys->id) {
            case SYSCALL_OPEN:
                syscall_pathname = (void *) sys->args.args[0];
                break;
            case SYSCALL_OPENAT:
            case SYSCALL_OPENAT2:
                syscall_pathname = (void *) sys->args.args[1];
                break;
        }
    }

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, (void *) GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);
    save_str_to_buf(p.event, syscall_pathname, 5);
    save_to_submit_buf(p.event, (void *) &sys->id, sizeof(int), 6);

    return events_perf_submit(&p, SECURITY_FILE_OPEN, 0);
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_security_sb_mount)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SB_MOUNT, &(p.event->context)))
        return 0;

    const char *dev_name = (const char *) PT_REGS_PARM1(ctx);
    struct path *path = (struct path *) PT_REGS_PARM2(ctx);
    const char *type = (const char *) PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long) PT_REGS_PARM4(ctx);

    void *path_str = get_path_str(path);

    save_str_to_buf(p.event, (void *) dev_name, 0);
    save_str_to_buf(p.event, path_str, 1);
    save_str_to_buf(p.event, (void *) type, 2);
    save_to_submit_buf(p.event, &flags, sizeof(unsigned long), 3);

    return events_perf_submit(&p, SECURITY_SB_MOUNT, 0);
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_UNLINK, &(p.event->context)))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long inode_nr = get_inode_nr_from_dentry(dentry);
    dev_t dev = get_dev_from_dentry(dentry);
    u64 ctime = get_ctime_nanosec_from_dentry(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 1);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 3);

    return events_perf_submit(&p, SECURITY_INODE_UNLINK, 0);
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(COMMIT_CREDS, &(p.event->context)))
        return 0;

    struct cred *new = (struct cred *) PT_REGS_PARM1(ctx);
    struct cred *old = (struct cred *) get_task_real_cred(p.event->task);

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

    save_to_submit_buf(p.event, (void *) &old_slim, sizeof(slim_cred_t), 0);
    save_to_submit_buf(p.event, (void *) &new_slim, sizeof(slim_cred_t), 1);

    if ((old_slim.uid != new_slim.uid) || (old_slim.gid != new_slim.gid) ||
        (old_slim.suid != new_slim.suid) || (old_slim.sgid != new_slim.sgid) ||
        (old_slim.euid != new_slim.euid) || (old_slim.egid != new_slim.egid) ||
        (old_slim.fsuid != new_slim.fsuid) || (old_slim.fsgid != new_slim.fsgid) ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable) ||
        (old_slim.cap_permitted != new_slim.cap_permitted) ||
        (old_slim.cap_effective != new_slim.cap_effective) ||
        (old_slim.cap_bset != new_slim.cap_bset) ||
        (old_slim.cap_ambient != new_slim.cap_ambient)) {
        int id = get_task_syscall_id(p.event->task);
        save_to_submit_buf(p.event, (void *) &id, sizeof(int), 2);

        events_perf_submit(&p, COMMIT_CREDS, 0);
    }

    return 0;
}

SEC("kprobe/switch_task_namespaces")
int BPF_KPROBE(trace_switch_task_namespaces)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SWITCH_TASK_NS, &(p.event->context)))
        return 0;

    struct task_struct *task = (struct task_struct *) PT_REGS_PARM1(ctx);
    struct nsproxy *new = (struct nsproxy *) PT_REGS_PARM2(ctx);

    if (!new)
        return 0;

    pid_t pid = READ_KERN(task->pid);
    u32 old_mnt = p.event->context.task.mnt_id;
    u32 new_mnt = get_mnt_ns_id(new);
    u32 old_pid = get_task_pid_ns_for_children_id(task);
    u32 new_pid = get_pid_ns_for_children_id(new);
    u32 old_uts = get_task_uts_ns_id(task);
    u32 new_uts = get_uts_ns_id(new);
    u32 old_ipc = get_task_ipc_ns_id(task);
    u32 new_ipc = get_ipc_ns_id(new);
    u32 old_net = get_task_net_ns_id(task);
    u32 new_net = get_net_ns_id(new);
    u32 old_cgroup = get_task_cgroup_ns_id(task);
    u32 new_cgroup = get_cgroup_ns_id(new);

    save_to_submit_buf(p.event, (void *) &pid, sizeof(int), 0);

    if (old_mnt != new_mnt)
        save_to_submit_buf(p.event, (void *) &new_mnt, sizeof(u32), 1);
    if (old_pid != new_pid)
        save_to_submit_buf(p.event, (void *) &new_pid, sizeof(u32), 2);
    if (old_uts != new_uts)
        save_to_submit_buf(p.event, (void *) &new_uts, sizeof(u32), 3);
    if (old_ipc != new_ipc)
        save_to_submit_buf(p.event, (void *) &new_ipc, sizeof(u32), 4);
    if (old_net != new_net)
        save_to_submit_buf(p.event, (void *) &new_net, sizeof(u32), 5);
    if (old_cgroup != new_cgroup)
        save_to_submit_buf(p.event, (void *) &new_cgroup, sizeof(u32), 6);
    if (p.event->context.argnum > 1)
        events_perf_submit(&p, SWITCH_TASK_NS, 0);

    return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CAP_CAPABLE, &(p.event->context)))
        return 0;

    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(p.event, (void *) &cap, sizeof(int), 0);
    int id = get_task_syscall_id(p.event->task);
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 1);

    return events_perf_submit(&p, CAP_CAPABLE, 0);
}

SEC("kprobe/security_socket_create")
int BPF_KPROBE(trace_security_socket_create)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_CREATE, &(p.event->context)))
        return 0;

    int family = (int) PT_REGS_PARM1(ctx);
    int type = (int) PT_REGS_PARM2(ctx);
    int protocol = (int) PT_REGS_PARM3(ctx);
    int kern = (int) PT_REGS_PARM4(ctx);

    save_to_submit_buf(p.event, (void *) &family, sizeof(int), 0);
    save_to_submit_buf(p.event, (void *) &type, sizeof(int), 1);
    save_to_submit_buf(p.event, (void *) &protocol, sizeof(int), 2);
    save_to_submit_buf(p.event, (void *) &kern, sizeof(int), 3);

    return events_perf_submit(&p, SECURITY_SOCKET_CREATE, 0);
}

SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(trace_security_inode_symlink)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_SYMLINK, &(p.event->context)))
        return 0;

    // struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    const char *old_name = (const char *) PT_REGS_PARM3(ctx);

    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_str_to_buf(p.event, (void *) old_name, 1);

    return events_perf_submit(&p, SECURITY_INODE_SYMLINK, 0);
}

SEC("kprobe/proc_create")
int BPF_KPROBE(trace_proc_create)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(PROC_CREATE, &(p.event->context)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM4(ctx);

    save_str_to_buf(p.event, name, 0);
    save_to_submit_buf(p.event, (void *) &proc_ops_addr, sizeof(u64), 1);

    return events_perf_submit(&p, PROC_CREATE, 0);
}

SEC("kprobe/debugfs_create_file")
int BPF_KPROBE(trace_debugfs_create_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(DEBUGFS_CREATE_FILE, &(p.event->context)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    mode_t mode = (unsigned short) PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM3(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    unsigned long proc_ops_addr = (unsigned long) PT_REGS_PARM5(ctx);

    save_str_to_buf(p.event, name, 0);
    save_str_to_buf(p.event, dentry_path, 1);
    save_to_submit_buf(p.event, &mode, sizeof(mode_t), 2);
    save_to_submit_buf(p.event, (void *) &proc_ops_addr, sizeof(u64), 3);

    return events_perf_submit(&p, DEBUGFS_CREATE_FILE, 0);
}

SEC("kprobe/debugfs_create_dir")
int BPF_KPROBE(trace_debugfs_create_dir)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(DEBUGFS_CREATE_DIR, &(p.event->context)))
        return 0;

    char *name = (char *) PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(p.event, name, 0);
    save_str_to_buf(p.event, dentry_path, 1);

    return events_perf_submit(&p, DEBUGFS_CREATE_DIR, 0);
}

SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_LISTEN, &(p.event->context)))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int backlog = (int) PT_REGS_PARM2(ctx);

    // Load the arguments given to the listen syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_LISTEN)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);
    save_sockaddr_to_buf(p.event, sock, 1);
    save_to_submit_buf(p.event, (void *) &backlog, sizeof(int), 2);

    return events_perf_submit(&p, SECURITY_SOCKET_LISTEN, 0);
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_CONNECT, &(p.event->context)))
        return 0;

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
#if defined(__TARGET_ARCH_x86) // TODO: issue: #1129
    uint addr_len = (uint) PT_REGS_PARM3(ctx);
#endif

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the connect syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_CONNECT)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);

    if (sa_fam == AF_INET) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in), 1);
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in6), 1);
    } else if (sa_fam == AF_UNIX) {
#if defined(__TARGET_ARCH_x86) // TODO: this is broken in arm64 (issue: #1129)
        if (addr_len <= sizeof(struct sockaddr_un)) {
            struct sockaddr_un sockaddr = {};
            bpf_probe_read(&sockaddr, addr_len, (void *) address);
            save_to_submit_buf(p.event, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&p, SECURITY_SOCKET_CONNECT, 0);
}

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);

    struct socket *new_sock = (struct socket *) PT_REGS_PARM2(ctx);

    // save sockets for "socket_accept event"
    if (should_submit(SOCKET_ACCEPT, &(p.event->context))) {
        args_t args = {};
        args.args[0] = (unsigned long) sock;
        args.args[1] = (unsigned long) new_sock;
        save_args(&args, SOCKET_ACCEPT);
    }

    if (!should_submit(SECURITY_SOCKET_ACCEPT, &(p.event->context)))
        return 0;

    // Load the arguments given to the accept syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || (sys->id != SYSCALL_ACCEPT && sys->id != SYSCALL_ACCEPT4))
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);
    save_sockaddr_to_buf(p.event, sock, 1);

    return events_perf_submit(&p, SECURITY_SOCKET_ACCEPT, 0);
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_BIND, &(p.event->context)))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    struct sock *sk = get_socket_sock(sock);

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
#if defined(__TARGET_ARCH_x86) // TODO: issue: #1129
    uint addr_len = (uint) PT_REGS_PARM3(ctx);
#endif

    sa_family_t sa_fam = get_sockaddr_family(address);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }

    // Load the arguments given to the bind syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_BIND)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);

    u16 protocol = get_sock_protocol(sk);
    net_id_t connect_id = {0};
    connect_id.protocol = protocol;

    if (sa_fam == AF_INET) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in), 1);

        struct sockaddr_in *addr = (struct sockaddr_in *) address;

        if (protocol == IPPROTO_UDP && READ_KERN(addr->sin_port)) {
            connect_id.address.s6_addr32[3] = READ_KERN(addr->sin_addr).s_addr;
            connect_id.address.s6_addr16[5] = 0xffff;
            connect_id.port = READ_KERN(addr->sin_port);
        }
    } else if (sa_fam == AF_INET6) {
        save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_in6), 1);

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
            save_to_submit_buf(p.event, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
        } else
#endif
            save_to_submit_buf(p.event, (void *) address, sizeof(struct sockaddr_un), 1);
    }

    return events_perf_submit(&p, SECURITY_SOCKET_BIND, 0);
}

SEC("kprobe/security_socket_setsockopt")
int BPF_KPROBE(trace_security_socket_setsockopt)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_SOCKET_SETSOCKOPT, &(p.event->context)))
        return 0;

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    int level = (int) PT_REGS_PARM2(ctx);
    int optname = (int) PT_REGS_PARM3(ctx);

    // Load the arguments given to the setsockopt syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (sys == NULL) {
        return -1;
    }

    if (!p.task_info->syscall_traced || sys->id != SYSCALL_SETSOCKOPT)
        return 0;

    save_to_submit_buf(p.event, (void *) &sys->args.args[0], sizeof(u32), 0);
    save_to_submit_buf(p.event, (void *) &level, sizeof(int), 1);
    save_to_submit_buf(p.event, (void *) &optname, sizeof(int), 2);
    save_sockaddr_to_buf(p.event, sock, 3);

    return events_perf_submit(&p, SECURITY_SOCKET_SETSOCKOPT, 0);
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
submit_magic_write(program_data_t *p, file_info_t *file_info, io_data_t io_data, u32 bytes_written)
{
    u32 header_bytes = FILE_MAGIC_HDR_SIZE;
    if (header_bytes > bytes_written)
        header_bytes = bytes_written;

    p->event->buf_off = 0;
    p->event->context.argnum = 0;

    u8 header[FILE_MAGIC_HDR_SIZE];
    __builtin_memset(&header, 0, sizeof(header));

    save_str_to_buf(p->event, file_info->pathname_p, 0);

    if (io_data.is_buf) {
        if (header_bytes < FILE_MAGIC_HDR_SIZE)
            bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, io_data.ptr);
        else
            bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, io_data.ptr);
    } else {
        struct iovec io_vec;
        __builtin_memset(&io_vec, 0, sizeof(io_vec));
        bpf_probe_read(&io_vec, sizeof(struct iovec), io_data.ptr);
        if (header_bytes < FILE_MAGIC_HDR_SIZE)
            bpf_probe_read(header, header_bytes & FILE_MAGIC_MASK, io_vec.iov_base);
        else
            bpf_probe_read(header, FILE_MAGIC_HDR_SIZE, io_vec.iov_base);
    }

    save_bytes_to_buf(p->event, header, header_bytes, 1);
    save_to_submit_buf(p->event, &file_info->device, sizeof(dev_t), 2);
    save_to_submit_buf(p->event, &file_info->inode, sizeof(unsigned long), 3);

    // Submit magic_write event
    return events_perf_submit(p, MAGIC_WRITE, bytes_written);
}

static __always_inline bool should_submit_io_event(u32 event_id, program_data_t *p)
{
    return ((event_id == VFS_READ || event_id == VFS_READV || event_id == VFS_WRITE ||
             event_id == VFS_WRITEV || event_id == __KERNEL_WRITE) &&
            should_submit(event_id, &(p->event->context)));
}

/** do_file_io_operation - generic file IO (read and write) event creator.
 *
 * @ctx:            the state of the registers prior the hook.
 * @event_id:       the ID of the event to be created.
 * @tail_call_id:   the ID of the tail call to be called before function return.
 * @is_read:        true if the operation is read. False if write.
 * @is_buf:         true if the non-file side of the operation is a buffer. False if io_vector.
 */
static __always_inline int
do_file_io_operation(struct pt_regs *ctx, u32 event_id, u32 tail_call_id, bool is_read, bool is_buf)
{
    args_t saved_args;
    if (load_args(&saved_args, event_id) != 0) {
        // missed entry or not traced
        return 0;
    }

    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        del_args(event_id);
        return 0;
    }

    bool should_submit_magic_write = should_submit(MAGIC_WRITE, &(p.event->context));
    bool should_submit_io = should_submit_io_event(event_id, &p);

    if (!should_submit_io && !should_submit_magic_write) {
        bpf_tail_call(ctx, &prog_array, tail_call_id);
        del_args(event_id);
        return 0;
    }

    loff_t start_pos;
    io_data_t io_data;
    file_info_t file_info;

    struct file *file = (struct file *) saved_args.args[0];
    file_info.pathname_p = get_path_str(GET_FIELD_ADDR(file->f_path));

    io_data.is_buf = is_buf;
    io_data.ptr = (void *) saved_args.args[1];
    io_data.len = (unsigned long) saved_args.args[2];
    loff_t *pos = (loff_t *) saved_args.args[3];

    // Extract device id, inode number, and pos (offset)
    file_info.device = get_dev_from_file(file);
    file_info.inode = get_inode_nr_from_file(file);
    bpf_probe_read(&start_pos, sizeof(off_t), pos);

    bool char_dev = (start_pos == 0);
    u32 io_bytes_amount = PT_REGS_RC(ctx);

    // Calculate write start offset
    if (start_pos != 0)
        start_pos -= io_bytes_amount;

    if (should_submit_io) {
        save_str_to_buf(p.event, file_info.pathname_p, 0);
        save_to_submit_buf(p.event, &file_info.device, sizeof(dev_t), 1);
        save_to_submit_buf(p.event, &file_info.inode, sizeof(unsigned long), 2);
        save_to_submit_buf(p.event, &io_data.len, sizeof(unsigned long), 3);
        save_to_submit_buf(p.event, &start_pos, sizeof(off_t), 4);

        // Submit io event
        events_perf_submit(&p, event_id, PT_REGS_RC(ctx));
    }

    // magic_write event checks if the header of some file is changed
    if (!is_read && should_submit_magic_write && !char_dev && (start_pos == 0)) {
        submit_magic_write(&p, &file_info, io_data, io_bytes_amount);
    }

    bpf_tail_call(ctx, &prog_array, tail_call_id);
    del_args(event_id);
    return 0;
}

// Capture file write
// Will only capture if:
// 1. File write capture was configured
// 2. File matches the filters given
static __always_inline int capture_file_write(struct pt_regs *ctx, u32 event_id)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        del_args(event_id);
        return 0;
    }

    if ((p.config->options & OPT_CAPTURE_FILES) == 0) {
        del_args(event_id);
        return 0;
    }

    args_t saved_args;
    bin_args_t bin_args = {};
    loff_t start_pos;

    void *ptr;
    struct iovec *vec;
    unsigned long vlen;
    bool has_filter = false;
    bool filter_match = false;

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

    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    if (p.event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE)
        return -1;
    bpf_probe_read_str(&(p.event->args[p.event->buf_off]), MAX_STRING_SIZE, file_path);

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

        if (p.event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE)
            break;

        if (has_prefix(
                filter_p->path, (char *) &p.event->args[p.event->buf_off], MAX_PATH_PREF_SIZE)) {
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
    u32 pid = p.event->context.task.pid;

    if (p.event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE)
        return -1;

    if (!has_prefix("/dev/null", (char *) &p.event->args[p.event->buf_off], 10))
        pid = 0;

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
    return 0;
}

SEC("kprobe/vfs_write")
TRACE_ENT_FUNC(vfs_write, VFS_WRITE);

SEC("kretprobe/vfs_write")
int BPF_KPROBE(trace_ret_vfs_write)
{
    return do_file_io_operation(ctx, VFS_WRITE, TAIL_VFS_WRITE, false, true);
}

SEC("kretprobe/vfs_write_tail")
int BPF_KPROBE(trace_ret_vfs_write_tail)
{
    return capture_file_write(ctx, VFS_WRITE);
}

SEC("kprobe/vfs_writev")
TRACE_ENT_FUNC(vfs_writev, VFS_WRITEV);

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(trace_ret_vfs_writev)
{
    return do_file_io_operation(ctx, VFS_WRITEV, TAIL_VFS_WRITEV, false, false);
}

SEC("kretprobe/vfs_writev_tail")
int BPF_KPROBE(trace_ret_vfs_writev_tail)
{
    return capture_file_write(ctx, VFS_WRITEV);
}

SEC("kprobe/__kernel_write")
TRACE_ENT_FUNC(kernel_write, __KERNEL_WRITE);

SEC("kretprobe/__kernel_write")
int BPF_KPROBE(trace_ret_kernel_write)
{
    return do_file_io_operation(ctx, __KERNEL_WRITE, TAIL_KERNEL_WRITE, false, true);
}

SEC("kretprobe/__kernel_write_tail")
int BPF_KPROBE(trace_ret_kernel_write_tail)
{
    return capture_file_write(ctx, __KERNEL_WRITE);
}

SEC("kprobe/vfs_read")
TRACE_ENT_FUNC(vfs_read, VFS_READ);

SEC("kretprobe/vfs_read")
int BPF_KPROBE(trace_ret_vfs_read)
{
    return do_file_io_operation(ctx, VFS_READ, TAIL_VFS_READ, true, true);
}

SEC("kprobe/vfs_readv")
TRACE_ENT_FUNC(vfs_readv, VFS_READV);

SEC("kretprobe/vfs_readv")
int BPF_KPROBE(trace_ret_vfs_readv)
{
    return do_file_io_operation(ctx, VFS_READV, TAIL_VFS_READV, true, false);
}

SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_alert)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    // Load the arguments given to the mmap syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced || sys->id != SYSCALL_MMAP)
        return 0;

    int prot = sys->args.args[2];

    if ((prot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC) &&
        should_submit(MEM_PROT_ALERT, &(p.event->context))) {
        u32 alert = ALERT_MMAP_W_X;
        int fd = sys->args.args[5];
        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];
        struct file *file = get_struct_file_from_fd(fd);
        int prev_prot = 0;
        file_info_t file_info = get_file_info(file);
        submit_mem_prot_alert_event(p.event, alert, addr, len, prot, prev_prot, file_info);
    }

    return 0;
}

SEC("kprobe/do_mmap")
TRACE_ENT_FUNC(do_mmap, DO_MMAP)

SEC("kretprobe/do_mmap")
int BPF_KPROBE(trace_ret_do_mmap)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_submit(DO_MMAP, &(p.event->context)))
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, DO_MMAP) != 0) {
        // missed entry or not traced
        return 0;
    }

    dev_t s_dev;
    unsigned long inode_nr;
    void *file_path;
    u64 ctime;
    unsigned int flags;

    struct file *file = (struct file *) saved_args.args[0];
    if (file != NULL) {
        s_dev = get_dev_from_file(file);
        inode_nr = get_inode_nr_from_file(file);
        file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
        ctime = get_ctime_nanosec_from_file(file);
    }
    unsigned long len = (unsigned long) saved_args.args[2];
    unsigned long prot = (unsigned long) saved_args.args[3];
    unsigned long mmap_flags = (unsigned long) saved_args.args[4];
    unsigned long pgoff = (unsigned long) saved_args.args[5];
    unsigned long addr = (unsigned long) PT_REGS_RC(ctx);

    save_to_submit_buf(p.event, &addr, sizeof(void *), 0);
    if (file != NULL) {
        save_str_to_buf(p.event, file_path, 1);
        save_to_submit_buf(p.event, &flags, sizeof(unsigned int), 2);
        save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 3);
        save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 4);
        save_to_submit_buf(p.event, &ctime, sizeof(u64), 5);
    }
    save_to_submit_buf(p.event, &pgoff, sizeof(unsigned long), 6);
    save_to_submit_buf(p.event, &len, sizeof(unsigned long), 7);
    save_to_submit_buf(p.event, &prot, sizeof(unsigned long), 8);
    save_to_submit_buf(p.event, &mmap_flags, sizeof(unsigned long), 9);
    int id = get_task_syscall_id(p.event->task);
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 10);

    return events_perf_submit(&p, DO_MMAP, 0);
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(trace_security_mmap_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    bool submit_sec_mmap_file = should_submit(SECURITY_MMAP_FILE, &(p.event->context));
    bool submit_shared_object_loaded = should_submit(SHARED_OBJECT_LOADED, &(p.event->context));

    if (!submit_sec_mmap_file && !submit_shared_object_loaded)
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

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, (void *) GET_FIELD_ADDR(file->f_flags), sizeof(int), 1);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);

    int id = -1;
    if (submit_shared_object_loaded) {
        id = get_task_syscall_id(p.event->task);
        if ((prot & VM_EXEC) == VM_EXEC && id == SYSCALL_MMAP) {
            events_perf_submit(&p, SHARED_OBJECT_LOADED, 0);
        }
    }

    if (submit_sec_mmap_file) {
        save_to_submit_buf(p.event, &prot, sizeof(unsigned long), 5);
        save_to_submit_buf(p.event, &mmap_flags, sizeof(unsigned long), 6);
        if (id == -1) { // if id wasn't checked yet, do so now.
            id = get_task_syscall_id(p.event->task);
        }
        save_to_submit_buf(p.event, (void *) &id, sizeof(int), 7);
        return events_perf_submit(&p, SECURITY_MMAP_FILE, 0);
    }

    return 0;
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_security_file_mprotect)
{
    bin_args_t bin_args = {};

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    // Load the arguments given to the mprotect syscall (which eventually invokes this function)
    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced ||
        (sys->id != SYSCALL_MPROTECT && sys->id != SYSCALL_PKEY_MPROTECT))
        return 0;

    int should_submit_mprotect = should_submit(SECURITY_FILE_MPROTECT, &(p.event->context));
    int should_submit_mem_prot_alert = should_submit(MEM_PROT_ALERT, &(p.event->context));

    if (!should_submit_mprotect && !should_submit_mem_prot_alert) {
        return 0;
    }

    struct vm_area_struct *vma = (struct vm_area_struct *) PT_REGS_PARM1(ctx);
    unsigned long reqprot = PT_REGS_PARM2(ctx);
    unsigned long prev_prot = get_vma_flags(vma);

    struct file *file = (struct file *) READ_KERN(vma->vm_file);
    file_info_t file_info = get_file_info(file);

    if (should_submit_mprotect) {
        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];

        save_str_to_buf(p.event, file_info.pathname_p, 0);
        save_to_submit_buf(p.event, &reqprot, sizeof(int), 1);
        save_to_submit_buf(p.event, &file_info.ctime, sizeof(u64), 2);
        save_to_submit_buf(p.event, &prev_prot, sizeof(int), 3);
        save_to_submit_buf(p.event, &addr, sizeof(void *), 4);
        save_to_submit_buf(p.event, &len, sizeof(size_t), 5);

        if (sys->id == SYSCALL_PKEY_MPROTECT) {
            int pkey = sys->args.args[3];
            save_to_submit_buf(p.event, &pkey, sizeof(int), 6);
        }

        events_perf_submit(&p, SECURITY_FILE_MPROTECT, 0);
    }

    if (should_submit_mem_prot_alert) {
        void *addr = (void *) sys->args.args[0];
        size_t len = sys->args.args[1];

        if (addr <= 0)
            return 0;

        // If length is 0, the current page permissions are changed
        if (len == 0)
            len = PAGE_SIZE;

        p.event->buf_off = 0;
        p.event->context.argnum = 0;
        u32 alert;
        bool should_alert = false;
        bool should_extract_code = false;

        if ((!(prev_prot & VM_EXEC)) && (reqprot & VM_EXEC)) {
            alert = ALERT_MPROT_X_ADD;
            should_alert = true;
        }

        if ((prev_prot & VM_EXEC) && !(prev_prot & VM_WRITE) &&
            ((reqprot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC))) {
            alert = ALERT_MPROT_W_ADD;
            should_alert = true;
        }

        if (((prev_prot & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)) && (reqprot & VM_EXEC) &&
            !(reqprot & VM_WRITE)) {
            alert = ALERT_MPROT_W_REM;
            should_alert = true;

            if (p.config->options & OPT_EXTRACT_DYN_CODE) {
                should_extract_code = true;
            }
        }
        if (should_alert) {
            submit_mem_prot_alert_event(p.event, alert, addr, len, reqprot, prev_prot, file_info);
        }
        if (should_extract_code) {
            bin_args.type = SEND_MPROTECT;
            bpf_probe_read(bin_args.metadata, sizeof(u64), &p.event->context.ts);
            bin_args.ptr = (char *) addr;
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
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    if (!p.task_info->syscall_traced)
        return -1;

    bin_args_t bin_args = {};

    u32 pid = p.event->context.task.host_pid;
    u64 dummy = 0;
    void *addr = (void *) sys->args.args[0];
    unsigned long len = (unsigned long) sys->args.args[1];

    if (p.config->options & OPT_CAPTURE_MODULES) {
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

// Check (CORE || (!CORE && kernel >= 5.7)) to compile successfully.
// (compiler will try to compile the func even if no execution path leads to it).
#if defined(CORE) || (!defined(CORE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)))
static __always_inline int do_check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd)
{
    if (cmd == BPF_LINK_CREATE) {
        u32 prog_fd = READ_KERN(attr->link_create.prog_fd);
        u32 perf_fd = READ_KERN(attr->link_create.target_fd);

        struct file *bpf_prog_file = get_struct_file_from_fd(prog_fd);
        struct file *perf_event_file = get_struct_file_from_fd(perf_fd);

        send_bpf_attach(p, bpf_prog_file, perf_event_file);
    }

    return 0;
}
#endif

static __always_inline int check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd)
{
// BPF_LINK_CREATE command was only introduced in kernel 5.7.
// nothing to check for kernels < 5.7.
#ifdef CORE
    if (bpf_core_field_exists(attr->link_create)) {
        do_check_bpf_link(p, attr, cmd);
    }
#else
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    do_check_bpf_link(p, attr, cmd);
    #endif
#endif

    return 0;
}

SEC("kprobe/security_bpf")
int BPF_KPROBE(trace_security_bpf)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    int cmd = (int) PT_REGS_PARM1(ctx);

    if (should_submit(SECURITY_BPF, &(p.event->context))) {
        // 1st argument == cmd (int)
        save_to_submit_buf(p.event, (void *) &cmd, sizeof(int), 0);

        events_perf_submit(&p, SECURITY_BPF, 0);
    }

    union bpf_attr *attr = (union bpf_attr *) PT_REGS_PARM2(ctx);

    check_bpf_link(&p, attr, cmd);

    return 0;
}

// arm_kprobe can't be hooked in arm64 architecture, use enable logic instead

static __always_inline int arm_kprobe_handler(struct pt_regs *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, KPROBE_ATTACH) != 0) {
        return 0;
    }
    del_args(KPROBE_ATTACH);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct kprobe *kp = (struct kprobe *) saved_args.args[0];
    unsigned int retcode = PT_REGS_RC(ctx);

    if (retcode)
        return 0; // register_kprobe() failed

    char *symbol_name = (char *) READ_KERN(kp->symbol_name);
    u64 pre_handler = (u64) READ_KERN(kp->pre_handler);
    u64 post_handler = (u64) READ_KERN(kp->post_handler);

    save_str_to_buf(p.event, (void *) symbol_name, 0);
    save_to_submit_buf(p.event, (void *) &pre_handler, sizeof(u64), 1);
    save_to_submit_buf(p.event, (void *) &post_handler, sizeof(u64), 2);

    return events_perf_submit(&p, KPROBE_ATTACH, 0);
}

// register_kprobe and enable_kprobe have same execution path, and both call
// arm_kprobe, which is the function we are interested in. Nevertheless, there
// is also another function, register_aggr_kprobes, that might be able to call
// arm_kprobe so, instead of hooking into enable_kprobe, we hook into
// register_kprobe covering all execution paths.

SEC("kprobe/register_kprobe")
TRACE_ENT_FUNC(register_kprobe, KPROBE_ATTACH);

SEC("kretprobe/register_kprobe")
int BPF_KPROBE(trace_ret_register_kprobe)
{
    return arm_kprobe_handler(ctx);
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(trace_security_bpf_map)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_BPF_MAP, &(p.event->context)))
        return 0;

    struct bpf_map *map = (struct bpf_map *) PT_REGS_PARM1(ctx);

    // 1st argument == map_id (u32)
    save_to_submit_buf(p.event, (void *) GET_FIELD_ADDR(map->id), sizeof(int), 0);
    // 2nd argument == map_name (const char *)
    save_str_to_buf(p.event, (void *) GET_FIELD_ADDR(map->name), 1);

    return events_perf_submit(&p, SECURITY_BPF_MAP, 0);
}

SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(trace_security_bpf_prog)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct bpf_prog *prog = (struct bpf_prog *) PT_REGS_PARM1(ctx);
    struct bpf_prog_aux *prog_aux = READ_KERN(prog->aux);
    u32 prog_id = READ_KERN(prog_aux->id);

    bpf_attach_t val = {};
    // In some systems, the 'check_map_func_compatibility' and 'check_helper_call' symbols are not
    // available. For these cases, the temporary map 'bpf_attach_tmp_map' will not hold any
    // information (WRITE_USER_FALSE/WRITE_USER_TRUE). nevertheless, we always want to output the
    // 'bpf_attach' event to the user, so using the WRITE_USER_UNKNOWN value instead of returning,
    // just so the map would be filled.
    val.write_user = WRITE_USER_UNKNOWN;

    bpf_attach_t *existing_val;
    existing_val = bpf_map_lookup_elem(&bpf_attach_tmp_map, &p.event->context.task.host_tid);
    if (existing_val != NULL)
        val.write_user = existing_val->write_user;

    bpf_map_update_elem(&bpf_attach_map, &prog_id, &val, BPF_ANY);

    bpf_map_delete_elem(&bpf_attach_tmp_map, &p.event->context.task.host_tid);

    return 0;
}

// Save in the temporary map 'bpf_attach_tmp_map' whether or not bpf_probe_write_user is used in the
// bpf program. Get this information in the verifier phase of the bpf program load lifecycle, before
// a prog_id is set for the bpf program. Save this information in a temporary map which includes the
// host_tid as key instead of the prog_id.
//
// Later on, in security_bpf_prog, save this information in the stable map 'bpf_attach_map', which
// contains the prog_id in its key.

static __always_inline int handle_bpf_helper_func_id(u32 host_tid, int func_id)
{
    bpf_attach_t val = {};
    val.write_user = WRITE_USER_FALSE;

    bpf_attach_t *existing_val = bpf_map_lookup_elem(&bpf_attach_tmp_map, &host_tid);
    if (existing_val == NULL)
        bpf_map_update_elem(&bpf_attach_tmp_map, &host_tid, &val, BPF_ANY);

    if (func_id == BPF_FUNC_probe_write_user) {
        val.write_user = WRITE_USER_TRUE;
        bpf_map_update_elem(&bpf_attach_tmp_map, &host_tid, &val, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/check_map_func_compatibility")
int BPF_KPROBE(trace_check_map_func_compatibility)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    int func_id = (int) PT_REGS_PARM3(ctx);

    return handle_bpf_helper_func_id(p.event->context.task.host_tid, func_id);
}

SEC("kprobe/check_helper_call")
int BPF_KPROBE(trace_check_helper_call)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    int func_id;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0))
    func_id = (int) PT_REGS_PARM2(ctx);
#else
    struct bpf_insn *insn = (struct bpf_insn *) PT_REGS_PARM2(ctx);
    func_id = READ_KERN(insn->imm);
#endif

    return handle_bpf_helper_func_id(p.event->context.task.host_tid, func_id);
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_KERNEL_READ_FILE, &(p.event->context)))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM2(ctx);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    u64 ctime = get_ctime_nanosec_from_file(file);

    save_str_to_buf(p.event, file_path, 0);
    save_to_submit_buf(p.event, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(p.event, &inode_nr, sizeof(unsigned long), 2);
    save_to_submit_buf(p.event, &type_id, sizeof(int), 3);
    save_to_submit_buf(p.event, &ctime, sizeof(u64), 4);

    return events_perf_submit(&p, SECURITY_KERNEL_READ_FILE, 0);
}

SEC("kprobe/security_kernel_post_read_file")
int BPF_KPROBE(trace_security_kernel_post_read_file)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    bin_args_t bin_args = {};
    u64 id = bpf_get_current_pid_tgid();

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    u32 pid = p.event->context.task.host_pid;

    char *buf = (char *) PT_REGS_PARM2(ctx);
    loff_t size = (loff_t) PT_REGS_PARM3(ctx);
    enum kernel_read_file_id type_id = (enum kernel_read_file_id) PT_REGS_PARM4(ctx);

    // Send event if chosen
    if (should_submit(SECURITY_POST_READ_FILE, &(p.event->context))) {
        void *file_path = get_path_str(&file->f_path);
        save_str_to_buf(p.event, file_path, 0);
        save_to_submit_buf(p.event, &size, sizeof(loff_t), 1);
        save_to_submit_buf(p.event, &type_id, sizeof(int), 2);
        events_perf_submit(&p, SECURITY_POST_READ_FILE, 0);
    }

    if (p.config->options & OPT_CAPTURE_MODULES) {
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
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_MKNOD, &(p.event->context)))
        return 0;

    struct dentry *dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    unsigned short mode = (unsigned short) PT_REGS_PARM3(ctx);
    unsigned int dev = (unsigned int) PT_REGS_PARM4(ctx);
    void *dentry_path = get_dentry_path_str(dentry);

    save_str_to_buf(p.event, dentry_path, 0);
    save_to_submit_buf(p.event, &mode, sizeof(unsigned short), 1);
    save_to_submit_buf(p.event, &dev, sizeof(dev_t), 2);

    return events_perf_submit(&p, SECURITY_INODE_MKNOD, 0);
}

SEC("kprobe/device_add")
int BPF_KPROBE(trace_device_add)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DEVICE_ADD, &(p.event->context)))
        return 0;

    struct device *dev = (struct device *) PT_REGS_PARM1(ctx);
    const char *name = get_device_name(dev);

    struct device *parent_dev = READ_KERN(dev->parent);
    const char *parent_name = get_device_name(parent_dev);

    save_str_to_buf(p.event, (void *) name, 0);
    save_str_to_buf(p.event, (void *) parent_name, 1);

    return events_perf_submit(&p, DEVICE_ADD, 0);
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

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(REGISTER_CHRDEV, &(p.event->context)))
        return 0;

    unsigned int major_number = (unsigned int) saved_args.args[0];
    unsigned int returned_major = PT_REGS_RC(ctx);

    // sets the returned major to the requested one in case of a successful registration
    if (major_number > 0 && returned_major == 0) {
        returned_major = major_number;
    }

    char *char_device_name = (char *) saved_args.args[3];
    struct file_operations *char_device_fops = (struct file_operations *) saved_args.args[4];

    save_to_submit_buf(p.event, &major_number, sizeof(unsigned int), 0);
    save_to_submit_buf(p.event, &returned_major, sizeof(unsigned int), 1);
    save_str_to_buf(p.event, char_device_name, 2);
    save_to_submit_buf(p.event, &char_device_fops, sizeof(void *), 3);

    return events_perf_submit(&p, REGISTER_CHRDEV, 0);
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
// The Dirty Pipe vulnerability exist in the kernel since version 5.8, so there is not use to do
// logic if version is too old. In non-CORE, it will even mean using defines which are not available
// in the kernel headers, which will cause bugs.
#if !defined(CORE) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
    del_args(DIRTY_PIPE_SPLICE);
    return 0;
#else
    #ifdef CORE
    // Check if field of struct exist to determine kernel version - some fields change between
    // versions. In version 5.8 of the kernel, the field "high_zoneidx" changed its name to
    // "highest_zoneidx". This means that the existence of the field "high_zoneidx" can indicate
    // that the kernel version is lower than v5.8
    struct alloc_context *check_508;
    if (bpf_core_field_exists(check_508->high_zoneidx)) {
        del_args(DIRTY_PIPE_SPLICE);
        return 0;
    }
    #endif // CORE

    args_t saved_args;
    if (load_args(&saved_args, DIRTY_PIPE_SPLICE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(DIRTY_PIPE_SPLICE);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DIRTY_PIPE_SPLICE, &(p.event->context)))
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

    save_to_submit_buf(p.event, &in_inode_number, sizeof(u64), 0);
    save_to_submit_buf(p.event, &in_file_type, sizeof(unsigned short), 1);
    save_str_to_buf(p.event, in_file_path, 2);
    save_to_submit_buf(p.event, &current_file_offset, sizeof(loff_t), 3);
    save_to_submit_buf(p.event, &exposed_data_len, sizeof(size_t), 4);
    save_to_submit_buf(p.event, &out_inode_number, sizeof(u64), 5);
    save_to_submit_buf(p.event, &out_pipe_last_buffer_flags, sizeof(unsigned int), 6);

    return events_perf_submit(&p, DIRTY_PIPE_SPLICE, 0);
#endif     // CORE && Version < 5.8
}

SEC("kprobe/do_init_module")
int BPF_KPROBE(trace_do_init_module)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
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
    bpf_map_update_elem(&module_init_map, &p.event->context.task.host_tid, &module_data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_init_module")
int BPF_KPROBE(trace_ret_do_init_module)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;
    if (!should_submit(DO_INIT_MODULE, &(p.event->context)))
        return 0;

    kmod_data_t *orig_module_data =
        bpf_map_lookup_elem(&module_init_map, &p.event->context.task.host_tid);
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
    save_str_to_buf(p.event, &orig_module_data->name, 0);
    save_str_to_buf(p.event, &orig_module_data->version, 1);
    save_str_to_buf(p.event, &orig_module_data->srcversion, 2);
    // save pointers to buf
    save_to_submit_buf(p.event, &(orig_module_data->prev), sizeof(u64), 3);
    save_to_submit_buf(p.event, &(orig_module_data->next), sizeof(u64), 4);
    save_to_submit_buf(p.event, &orig_prev_next_addr, sizeof(u64), 5);
    save_to_submit_buf(p.event, &orig_next_prev_addr, sizeof(u64), 6);

    events_perf_submit(&p, DO_INIT_MODULE, 0);

    // delete module data from map after it was used
    bpf_map_delete_elem(&module_init_map, &p.event->context.task.host_tid);

    return 0;
}

SEC("kprobe/load_elf_phdrs")
int BPF_KPROBE(trace_load_elf_phdrs)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &p.event->context.task.host_pid);
    if (unlikely(proc_info == NULL)) {
        // entry should exist in proc_map (init_program_data should have set it otherwise)
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    struct file *loaded_elf = (struct file *) PT_REGS_PARM2(ctx);
    const char *elf_pathname = (char *) get_path_str(GET_FIELD_ADDR(loaded_elf->f_path));

    // The interpreter field will be updated for any loading of an elf, both for the binary
    // and for the interpreter. Because the interpreter is loaded only after the executed elf is
    // loaded, the value of the executed binary should be overridden by the interpreter.
    size_t sz = sizeof(proc_info->interpreter.pathname);
    bpf_probe_read_str(proc_info->interpreter.pathname, sz, elf_pathname);
    proc_info->interpreter.device = get_dev_from_file(loaded_elf);
    proc_info->interpreter.inode = get_inode_nr_from_file(loaded_elf);
    proc_info->interpreter.ctime = get_ctime_nanosec_from_file(loaded_elf);

    if (should_submit(LOAD_ELF_PHDRS, &(p.event->context))) {
        save_str_to_buf(p.event, (void *) elf_pathname, 0);
        save_to_submit_buf(p.event, &proc_info->interpreter.device, sizeof(dev_t), 1);
        save_to_submit_buf(p.event, &proc_info->interpreter.inode, sizeof(unsigned long), 2);

        events_perf_submit(&p, LOAD_ELF_PHDRS, 0);
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

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(HOOKED_PROC_FOPS, &(p.event->context)))
        return 0;

    struct file_operations *fops = (struct file_operations *) READ_KERN(f_inode->i_fop);
    if (fops == NULL)
        return 0;

    unsigned long iterate_shared_addr = (unsigned long) READ_KERN(fops->iterate_shared);
    unsigned long iterate_addr = (unsigned long) READ_KERN(fops->iterate);
    if (iterate_addr == 0 && iterate_shared_addr == 0)
        return 0;

    // get text segment bounds
    void *stext_addr = get_stext_addr();
    if (unlikely(stext_addr == NULL))
        return 0;
    void *etext_addr = get_etext_addr();
    if (unlikely(etext_addr == NULL))
        return 0;

    // mark as 0 if in bounds
    if (iterate_shared_addr >= (u64) stext_addr && iterate_shared_addr < (u64) etext_addr)
        iterate_shared_addr = 0;
    if (iterate_addr >= (u64) stext_addr && iterate_addr < (u64) etext_addr)
        iterate_addr = 0;

    // now check again, if both are in text bounds, return
    if (iterate_addr == 0 && iterate_shared_addr == 0)
        return 0;

    unsigned long fops_addresses[2] = {iterate_shared_addr, iterate_addr};

    save_u64_arr_to_buf(p.event, (const u64 *) fops_addresses, 2, 0);
    events_perf_submit(&p, HOOKED_PROC_FOPS, 0);
    return 0;
}

SEC("raw_tracepoint/task_rename")
int tracepoint__task__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace((&p)))
        return 0;

    if (!should_submit(TASK_RENAME, &(p.event->context)))
        return 0;

    struct task_struct *tsk = (struct task_struct *) ctx->args[0];
    char old_name[TASK_COMM_LEN];
    bpf_probe_read_str(&old_name, TASK_COMM_LEN, tsk->comm);
    const char *new_name = (const char *) ctx->args[1];

    save_str_to_buf(p.event, (void *) old_name, 0);
    save_str_to_buf(p.event, (void *) new_name, 1);
    int id = get_task_syscall_id(tsk);
    save_to_submit_buf(p.event, (void *) &id, sizeof(int), 2);

    return events_perf_submit(&p, TASK_RENAME, 0);
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(trace_security_inode_rename)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_INODE_RENAME, &(p.event->context)))
        return 0;

    struct dentry *old_dentry = (struct dentry *) PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *) PT_REGS_PARM4(ctx);

    void *old_dentry_path = get_dentry_path_str(old_dentry);
    void *new_dentry_path = get_dentry_path_str(new_dentry);
    save_str_to_buf(p.event, old_dentry_path, 0);
    save_str_to_buf(p.event, new_dentry_path, 1);
    return events_perf_submit(&p, SECURITY_INODE_RENAME, 0);
}

SEC("kprobe/kallsyms_lookup_name")
TRACE_ENT_FUNC(kallsyms_lookup_name, KALLSYMS_LOOKUP_NAME);

SEC("kretprobe/kallsyms_lookup_name")
int BPF_KPROBE(trace_ret_kallsyms_lookup_name)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, KALLSYMS_LOOKUP_NAME) != 0)
        return 0;
    del_args(KALLSYMS_LOOKUP_NAME);

    if (!should_submit(KALLSYMS_LOOKUP_NAME, &(p.event->context)))
        return 0;

    char *name = (char *) saved_args.args[0];
    unsigned long address = PT_REGS_RC(ctx);

    save_str_to_buf(p.event, name, 0);
    save_to_submit_buf(p.event, &address, sizeof(unsigned long), 1);
    int id = get_task_syscall_id(p.event->task);
    save_to_submit_buf(p.event, &id, sizeof(int), 2);

    return events_perf_submit(&p, KALLSYMS_LOOKUP_NAME, 0);
}

SEC("kprobe/do_sigaction")
int BPF_KPROBE(trace_do_sigaction)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(DO_SIGACTION, &(p.event->context)))
        return 0;

    // Initialize all relevant arguments values
    int sig = (int) PT_REGS_PARM1(ctx);
    u8 old_handle_method = 0, new_handle_method = 0;
    unsigned long new_sa_flags, old_sa_flags;
    void *new_sa_handler, *old_sa_handler;
    unsigned long new_sa_mask, old_sa_mask;

    // Extract old signal handler values
    struct task_struct *task = p.event->task;
    struct sighand_struct *sighand = READ_KERN(task->sighand);
    struct k_sigaction *sig_actions = &(sighand->action[0]);
    if (sig > 0 && sig < _NSIG) {
        struct k_sigaction *old_act = get_node_addr(sig_actions, sig - 1);
        old_sa_flags = READ_KERN(old_act->sa.sa_flags);
        // In 64-bit system there is only 1 node in the mask array
        old_sa_mask = READ_KERN(old_act->sa.sa_mask.sig[0]);
        old_sa_handler = READ_KERN(old_act->sa.sa_handler);
        if (old_sa_handler >= (void *) SIG_HND)
            old_handle_method = SIG_HND;
        else {
            old_handle_method = (u8) (old_sa_handler && 0xFF);
            old_sa_handler = NULL;
        }
    }

    // Check if a pointer for storing old signal handler is given
    struct k_sigaction *recv_old_act = (struct k_sigaction *) PT_REGS_PARM3(ctx);
    bool old_act_initialized = recv_old_act != NULL;

    // Extract new signal handler values if initialized
    struct k_sigaction *new_act = (struct k_sigaction *) PT_REGS_PARM2(ctx);
    bool new_act_initialized = new_act != NULL;
    if (new_act_initialized) {
        struct sigaction *new_sigaction = &new_act->sa;
        new_sa_flags = READ_KERN(new_sigaction->sa_flags);
        // In 64-bit system there is only 1 node in the mask array
        new_sa_mask = READ_KERN(new_sigaction->sa_mask.sig[0]);
        new_sa_handler = READ_KERN(new_sigaction->sa_handler);
        if (new_sa_handler >= (void *) SIG_HND)
            new_handle_method = SIG_HND;
        else {
            new_handle_method = (u8) (new_sa_handler && 0xFF);
            new_sa_handler = NULL;
        }
    }

    save_to_submit_buf(p.event, &sig, sizeof(int), 0);
    save_to_submit_buf(p.event, &new_act_initialized, sizeof(bool), 1);
    if (new_act_initialized) {
        save_to_submit_buf(p.event, &new_sa_flags, sizeof(unsigned long), 2);
        save_to_submit_buf(p.event, &new_sa_mask, sizeof(unsigned long), 3);
        save_to_submit_buf(p.event, &new_handle_method, sizeof(u8), 4);
        save_to_submit_buf(p.event, &new_sa_handler, sizeof(void *), 5);
    }
    save_to_submit_buf(p.event, &old_act_initialized, sizeof(bool), 6);
    save_to_submit_buf(p.event, &old_sa_flags, sizeof(unsigned long), 7);
    save_to_submit_buf(p.event, &old_sa_mask, sizeof(unsigned long), 8);
    save_to_submit_buf(p.event, &old_handle_method, sizeof(u8), 9);
    save_to_submit_buf(p.event, &old_sa_handler, sizeof(void *), 10);

    return events_perf_submit(&p, DO_SIGACTION, 0);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 0) || defined(CORE)) || defined(RHEL_RELEASE_CODE)

// Network Packets (works from ~5.2 and beyond)

// There are multiple ways to follow ingress/egress for a task. One way is to
// try to track all flows within network interfaces and keep a map of addresses
// tuples and translations. OR, sk_storage and socket cookies might help in
// understanding which sock/sk_buff context the bpf program is dealing with but,
// at the end, the need is always to tie a flow to a task (specially when
// hooking ingress skb bpf programs, when the current task is a kernel thread
// most of the times).

// Unfortunately that gets even more complicated in older kernels: the cgroup
// skb programs have almost no bpf helpers to use, and most of common code
// causes verifier to fail. With that in mind, this approach uses a technique of
// kprobing the function responsible for calling the cgroup/skb programs.

// All the work, that should be done by the cgroup/skb programs in the common
// case, in this case is done by this kprobe/kretprobe hook logic (right before
// and right after the cgroup/skb program runs). By doing that, all the data
// that cgroup/skb programs need to use is already placed in a map.

// Obviously this has some cons: this kprobe->cgroup/skb->kretprobe execution
// flow does not have preemption disabled, so the map used in between the 3
// hooks need to use something that is available to all 3 of them.

// At the end, the logic is simple: every time a socket is created an inode is
// also created. The task owning the socket is indexed by the socket inode so
// everytime this socket is used we know which task it belongs to (specially
// during ingress hook).

//
// network helper functions
//

static __always_inline bool is_socket_supported(struct socket *sock)
{
    // clang-format off
    struct sock *sk = (void *) BPF_READ(sock, sk);
    u16 protocol = get_sock_protocol(sk);
    switch (protocol) {
        // case IPPROTO_IPV6:
        // case IPPROTO_IPIP:
        // case IPPROTO_DCCP:
        // case IPPROTO_SCTP:
        // case IPPROTO_UDPLITE:
        case IPPROTO_IP:
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            break;
        default:
            return 0;
    }

    return 1;
    // clang-format on
}

//
// network related maps
//

// clang-format off

// cgroupctxmap

typedef enum net_packet {
    CAP_NET_PACKET = 1 << 0,
    // Layer 3
    SUB_NET_PACKET_IP = 1 << 1,
    // Layer 4
    SUB_NET_PACKET_TCP = 1 << 2,
    SUB_NET_PACKET_UDP = 1<<3,
    SUB_NET_PACKET_ICMP = 1 <<4,
    SUB_NET_PACKET_ICMPV6 = 1<<5,
    // Layer 7
    SUB_NET_PACKET_DNS = 1<< 6,
    SUB_NET_PACKET_HTTP = 1<<7,
} net_packet_t;


typedef struct net_event_contextmd {
    u8 submit;
    u32 header_size;
    u8 captured;
    u8 padding;
} __attribute__((__packed__)) net_event_contextmd_t;

typedef struct net_event_context {
    event_context_t eventctx;
    struct { // event arguments (needs packing), use anonymous struct to ...
        u8 index0;
        u32 bytes;
        // ... (payload sent by bpf_perf_event_output)
    } __attribute__((__packed__)); // ... avoid address-of-packed-member warns
    // members bellow this point are metadata (not part of event to be sent)
    net_event_contextmd_t md;
} net_event_context_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);          // simultaneous cgroup/skb ingress/eggress progs
    __type(key, u64);                   // sk_buff timestamp
    __type(value, net_event_context_t); // event context built so cgroup/skb can use
} cgrpctxmap SEC(".maps");              // saved info between SKB caller and SKB program

// inodemap

typedef struct net_task_context {
    struct task_struct *task;
    task_context_t taskctx;
    u64 matched_scopes;
} net_task_context_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);             // simultaneous sockets being traced
    __type(key, u64);                       // socket inode number ...
    __type(value, struct net_task_context); // ... linked to a task context
} inodemap SEC(".maps");                    // relate sockets and tasks

// entrymap

typedef struct entry {
    long unsigned int args[6];
} entry_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);       // simultaneous tasks being traced for entry/exit
    __type(key, u32);                // host thread group id (tgid or tid) ...
    __type(value, struct entry);     // ... linked to entry ctx->args
} entrymap SEC(".maps");             // can't use args_map (indexed by existing events only)

// network capture events

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} net_cap_events SEC(".maps");

// scratch area

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);                    // simultaneous softirqs running per CPU (?)
    __type(key, u32);                          // per cpu index ... (always zero)
    __type(value, scratch_t);                  // ... linked to a scratch area
} net_heap_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);                    // simultaneous softirqs running per CPU (?)
    __type(key, u32);                          // per cpu index ... (always zero)
    __type(value, event_data_t);               // ... linked to a scratch area
} net_heap_event SEC(".maps");

// clang-format on

//
// support functions for network code
//

static __always_inline u64 sizeof_net_event_context_t(void)
{
    return sizeof(net_event_context_t) - sizeof(net_event_contextmd_t);
}

static __always_inline void set_net_task_context(event_data_t *event, net_task_context_t *netctx)
{
    netctx->task = event->task;
    netctx->matched_scopes = event->context.matched_scopes;
    __builtin_memset(&netctx->taskctx, 0, sizeof(task_context_t));
    __builtin_memcpy(&netctx->taskctx, &event->context.task, sizeof(task_context_t));
}

static __always_inline enum event_id_e net_packet_to_net_event(net_packet_t packet_type)
{
    switch (packet_type) {
        case CAP_NET_PACKET:
            return NET_PACKET_CAP_BASE;
        case SUB_NET_PACKET_IP:
            return NET_PACKET_IP;
        case SUB_NET_PACKET_TCP:
            return NET_PACKET_TCP;
        case SUB_NET_PACKET_UDP:
            return NET_PACKET_UDP;
        case SUB_NET_PACKET_ICMP:
            return NET_PACKET_ICMP;
        case SUB_NET_PACKET_ICMPV6:
            return NET_PACKET_ICMPV6;
        case SUB_NET_PACKET_DNS:
            return NET_PACKET_DNS;
        case SUB_NET_PACKET_HTTP:
            return NET_PACKET_HTTP;
    };
    return MAX_EVENT_ID;
}

static __always_inline int should_submit_net_event(net_event_context_t *neteventctx,
                                                   net_packet_t packet_type)
{
    // configure network events that should be sent to userland
    if (neteventctx->md.submit & packet_type)
        return 1;

    if (should_submit(net_packet_to_net_event(packet_type), &(neteventctx->eventctx))) {
        neteventctx->md.submit |= packet_type;
        // done, result cached for later.
        return 1;
    }
    return 0;
}

//
// Socket Creation: keep track of created socket inodes per traced task
//

SEC("kprobe/sock_alloc_file")
int BPF_KPROBE(trace_sock_alloc_file)
{
    // runs every time a socket is created (entry)

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct entry entry = {0};

    // save args for retprobe
    entry.args[0] = PT_REGS_PARM1(ctx); // struct socket *sock
    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    if (!is_socket_supported(sock))
        return 0;

    entry.args[1] = PT_REGS_PARM2(ctx); // int flags
    entry.args[2] = PT_REGS_PARM2(ctx); // char *dname

    // prepare for kretprobe using entrymap
    u32 host_tid = p.event->context.task.host_tid;
    bpf_map_update_elem(&entrymap, &host_tid, &entry, BPF_ANY);

    return 0;
}

SEC("kretprobe/sock_alloc_file")
int BPF_KRETPROBE(trace_ret_sock_alloc_file)
{
    // runs every time a socket is created (return)

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // pick from entry from entrymap
    u32 host_tid = p.event->context.task.host_tid;
    struct entry *entry = bpf_map_lookup_elem(&entrymap, &host_tid);
    if (!entry) // no entry == no tracing
        return 0;

    // pick args from entry point's entry
    // struct socket *sock = (void *) entry->args[0];
    // int flags = entry->args[1];
    // char *dname = (void *) entry->args[2];
    struct file *sock_file = (void *) PT_REGS_RC(ctx);

    // cleanup entrymap
    bpf_map_delete_elem(&entrymap, &host_tid);

    if (!sock_file)
        return 0; // socket() failed ?

    u64 inode = BPF_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save context to further create an event when no context exists
    net_task_context_t netctx = {0};
    set_net_task_context(p.event, &netctx);

    // update inodemap correlating inode <=> task
    bpf_map_update_elem(&inodemap, &inode, &netctx, BPF_ANY);

    return 0;
}

//
// Socket creation and socket <=> task context updates
//

static __always_inline u32 security_socket_send_recv_msg(struct socket *sock, event_data_t *event)
{
    if (!is_socket_supported(sock))
        return 0;

    struct file *sock_file = BPF_READ(sock, file);
    if (!sock_file)
        return 0;

    u64 inode = BPF_READ(sock_file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save updated context to the inode map (inode <=> task ctx relation)
    net_task_context_t netctx = {0};
    set_net_task_context(event, &netctx);
    bpf_map_update_elem(&inodemap, &inode, &netctx, BPF_ANY);

    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(trace_security_socket_recvmsg)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    return security_socket_send_recv_msg(sock, p.event);
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(trace_security_socket_sendmsg)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct socket *sock = (void *) PT_REGS_PARM1(ctx);

    return security_socket_send_recv_msg(sock, p.event);
}

    // network retval values
    #define family_ipv4     (1 << 0)
    #define family_ipv6     (1 << 1)
    #define proto_http_req  (1 << 2)
    #define proto_http_resp (1 << 3)

//
// Socket Ingress/Egress eBPF program loader (right before and right after eBPF)
//

SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(cgroup_bpf_run_filter_skb)
{
    // runs BEFORE the CGROUP/SKB eBPF program

    int type = PT_REGS_PARM3(ctx);
    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
        case BPF_CGROUP_INET_EGRESS:
            break;
        default:
            return 0; // wrong attachment type, return fast
    }

    u32 zero = 0;
    event_data_t *e = bpf_map_lookup_elem(&net_heap_event, &zero);
    if (unlikely(e == NULL))
        return 0;
    scratch_t *s = bpf_map_lookup_elem(&net_heap_scratch, &zero);
    if (unlikely(s == NULL))
        return 0;

    program_data_t p = {
        .event = e,
        .scratch = s,
    };
    if (!init_program_data(&p, ctx))
        return 0;

    struct sock *sk = (void *) PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (void *) PT_REGS_PARM2(ctx);

    // obtain socket inode
    u64 inode = BPF_READ(sk, sk_socket, file, f_inode, i_ino);
    if (inode == 0)
        return 0;

    // save args for kretprobe
    struct entry entry = {0};
    entry.args[0] = PT_REGS_PARM1(ctx); // struct sock *sk
    entry.args[1] = PT_REGS_PARM2(ctx); // struct sk_buff *skb

    // prepare for kretprobe using entrymap
    u32 host_tid = p.event->context.task.host_tid;
    bpf_map_update_elem(&entrymap, &host_tid, &entry, BPF_ANY);

    // pick network context from the inodemap (inode <=> task)
    net_task_context_t *netctx = bpf_map_lookup_elem(&inodemap, &inode);
    if (!netctx)
        return 0;

    // use skb timestamp as the key for cgroup/skb (*)
    u64 skbts = BPF_READ(skb, tstamp);

    // Prepare [event_context_t][args1,arg2,arg3...] to be sent by cgroup/skb
    // program. The [...] part of the event can't use existing per-cpu submit
    // buffer helpers because the time in between this kprobe fires and the
    // cgroup/skb program runs might be suffer a preemption.

    net_event_context_t neteventctx = {0}; // to be sent by cgroup/skb program
    event_context_t *eventctx = &neteventctx.eventctx;

    // copy orig task ctx (from the netctx) to event ctx and build the rest
    __builtin_memcpy(&eventctx->task, &netctx->taskctx, sizeof(task_context_t));
    eventctx->ts = p.event->context.ts;                     // copy timestamp from current ctx
    eventctx->argnum = 1;                                   // 1 argument (add more if needed)
    eventctx->eventid = NET_PACKET_IP;                      // will be changed in skb program
    eventctx->stack_id = 0;                                 // no stack trace
    eventctx->processor_id = p.event->context.processor_id; // copy from current ctx
    eventctx->matched_scopes = netctx->matched_scopes;      // pick matched-scopes from net ctx

    // inform userland about protocol family (for correct L3 header parsing)...
    struct sock_common *common = (void *) sk;
    u8 family = BPF_READ(common, skc_family);
    switch (family) {
        case AF_INET:
            eventctx->retval |= family_ipv4;
        case AF_INET6:
            eventctx->retval |= family_ipv6;
    }
    // ... through event ctx ret val

    // set event arguments
    neteventctx.bytes = 0; // no payload by default (changed inside skb prog)

    // (*) Use skb timestamp as the key for a map shared between this kprobe and
    // the skb ebpf program: this is **NOT SUPER** BUT, for older kernels, that
    // provide ABSOLUTE NO eBPF helpers in cgroup/skb programs context, it does
    // its job: pre-process everything HERE so cgroup/skb programs can use.
    //
    // Explanation: The cgroup/skb eBPF program is called right after this
    //              kprobe, but preemption is enabled. If preemption wasn't
    //              enabled, we could simply populate a single item map and pick
    //              pointer inside cgroup/skb. Instead, we index map items
    //              using the skb timestamp, which is a value that is shared
    //              among this kprobe AND the cgroup/skb program context
    //              (through its skbuf copy).
    //
    // Theoretically, map collisions might occur, BUT very unlikely due to:
    //
    // kprobe (map update) -> cgroup/skb (consume) -> kretprobe (map delete)

    bpf_map_update_elem(&cgrpctxmap, &skbts, &neteventctx, BPF_NOEXIST);

    return 0;
}

SEC("kretprobe/__cgroup_bpf_run_filter_skb")
int BPF_KRETPROBE(ret_cgroup_bpf_run_filter_skb)
{
    // runs AFTER the CGROUP/SKB eBPF program

    // pick from entry from entrymap
    u32 host_tid = bpf_get_current_pid_tgid();
    struct entry *entry = bpf_map_lookup_elem(&entrymap, &host_tid);
    if (!entry) // no entry == no tracing
        return 0;

    // pick args from entry point's entry
    // struct sock *sk = (void *) entry->args[0];
    struct sk_buff *skb = (void *) entry->args[1];

    // cleanup entrymap
    bpf_map_delete_elem(&entrymap, &host_tid);

    // use skb timestamp as the key for cgroup/skb
    u64 skbts = BPF_READ(skb, tstamp);

    // delete netctx after cgroup ebpf program runs
    bpf_map_delete_elem(&cgrpctxmap, &skbts);

    return 0;
}

//
// Type definitions and prototypes for protocol parsing
//

// NOTE: proto header structs need full type in vmlinux.h (for correct skb copy)

typedef union iphdrs_t {
    struct iphdr iphdr;
    struct ipv6hdr ipv6hdr;
} iphdrs;

typedef union protohdrs_t {
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmphdr icmphdr;
    struct icmp6hdr icmp6hdr;
    union {
        u8 tcp_extra[40]; // data offset might set it up to 60 bytes
    };
} protohdrs;

typedef struct nethdrs_t {
    iphdrs iphdrs;
    protohdrs protohdrs;
} nethdrs;

// clang-format off

#define CGROUP_SKB_HANDLE_FUNCTION(name)                                       \
static __always_inline u32 cgroup_skb_handle_##name(                           \
    struct __sk_buff *ctx,                                                     \
    net_event_context_t *neteventctx,                                          \
    nethdrs *nethdrs                                                           \
)

CGROUP_SKB_HANDLE_FUNCTION(family);
CGROUP_SKB_HANDLE_FUNCTION(proto);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_http);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_icmp);
CGROUP_SKB_HANDLE_FUNCTION(proto_icmpv6);

#define CGROUP_SKB_HANDLE(name) cgroup_skb_handle_##name(ctx, neteventctx, nethdrs);

//
// Network submission functions
//

#define FULL    65536 // 1 << 16
#define HEADERS 0     // no payload

static __always_inline u32 cgroup_skb_submit(void *map,
                                             struct __sk_buff *ctx,
                                             net_event_context_t *neteventctx,
                                             u32 event_type,
                                             u32 size)
{
    u64 flags = BPF_F_CURRENT_CPU;

    size = size > FULL ? FULL : size;
    switch (size) {
        case HEADERS:
            size = neteventctx->md.header_size;
            break;
        case FULL:
            size = ctx->len;
            break;
        default:
            size += neteventctx->md.header_size;       // add headers size
            size = size > ctx->len ? ctx->len : size;  // check limits
            break;
    }

    flags |= (u64) size << 32;
    neteventctx->bytes = size + sizeof(u32);

    // set the event type before submitting event
    neteventctx->eventctx.eventid = event_type;

    return bpf_perf_event_output(ctx,
                                 map,
                                 flags,
                                 neteventctx,
                                 sizeof_net_event_context_t());
}

#define cgroup_skb_submit_event(a,b,c,d) cgroup_skb_submit(&events,a,b,c,d)

static __always_inline u32 cgroup_skb_capture_event(struct __sk_buff *ctx,
                                                    net_event_context_t *neteventctx,
                                                    u32 event_type)
{
    int zero = 0;

    // pick network config map to know requested capture length
    netconfig_entry_t *nc = bpf_map_lookup_elem(&netconfig_map, &zero);
    if (nc == NULL)
        return 0;

    return cgroup_skb_submit(&net_cap_events,
                             ctx,
                             neteventctx,
                             event_type,
                             nc->capture_length);
}

// capture packet a single time (if passing through multiple protocols being submitted to userland)

#define cgroup_skb_capture() {                                                                     \
    if (should_submit_net_event(neteventctx, CAP_NET_PACKET) && neteventctx->md.captured == 0) {   \
        cgroup_skb_capture_event(ctx, neteventctx, NET_PACKET_CAP_BASE);                           \
        neteventctx->md.captured = 1;                                                              \
    }                                                                                              \
}

// clang-format on

//
// SKB eBPF programs
//

static __always_inline u32 cgroup_skb_generic(struct __sk_buff *ctx)
{
    // IMPORTANT: runs for EVERY packet of tasks belonging to root cgroup

    u64 skbts = ctx->tstamp; // use skb timestamp as key for cgroup/skb program

    net_event_context_t *neteventctx = bpf_map_lookup_elem(&cgrpctxmap, &skbts);
    if (!neteventctx)
        return 1;

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

    nethdrs hdrs = {0}, *nethdrs = &hdrs;

    return CGROUP_SKB_HANDLE(family);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx);
}

//
// Network Protocol Events Logic
//

// when guessing by src/dst ports, declare here

    #define UDP_PORT_DNS 53
    #define TCP_PORT_DNS 53

// when guessing through l7 layer, here

static __always_inline int net_l7_is_http(struct __sk_buff *skb, u32 l7_off)
{
    #define http_min_len 7 // longest http command is "DELETE "

    char http_min_str[http_min_len];
    __builtin_memset((void *) &http_min_str, 0, sizeof(char) * http_min_len);

    // load first http_min_len bytes from layer 7 in packet.
    if (bpf_skb_load_bytes(skb, l7_off, http_min_str, http_min_len) < 0) {
        return 0; // failed loading data into http_min_str - return.
    }

    // check if HTTP response
    if (has_prefix("HTTP/", http_min_str, 6)) {
        return proto_http_resp;
    }

    // clang-format off
    // check if HTTP request
    if (has_prefix("GET ", http_min_str, 5)    ||
        has_prefix("POST ", http_min_str, 6)   ||
        has_prefix("PUT ", http_min_str, 5)    ||
        has_prefix("DELETE ", http_min_str, 8) ||
        has_prefix("HEAD ", http_min_str, 6)) {
        return proto_http_req;
    }
    // clang-format on

    return 0;
}

//
// SUPPORTED SOCKET FAMILY TYPES (inet, inet6)
//

CGROUP_SKB_HANDLE_FUNCTION(family)
{
    void *dest;
    u32 size = 0;
    u32 family = ctx->family;

    switch (family) {
        case PF_INET:
            dest = &nethdrs->iphdrs.iphdr;
            size = get_type_size(struct iphdr);
            break;
        case PF_INET6:
            dest = &nethdrs->iphdrs.ipv6hdr;
            size = get_type_size(struct ipv6hdr);
            break;
        default:
            return 1; // other families are not an error
    }

    // load layer 3 protocol headers

    if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET))
        return 1;

    // recalculate IPv4 header after first load with read IHL field

    u32 ihl = 0;
    switch (family) {
        case PF_INET:
            ihl = nethdrs->iphdrs.iphdr.ihl;
            if (ihl > 5) { // IP header is bigger than 20 bytes (old compat mode)
                size -= get_type_size(struct iphdr);
                size += ihl * 4; // ihl * 32bit words = IP header size in bytes
                // load bytes again with the new header size in place
                if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET))
                    return 1;
            }
    }

    neteventctx->md.header_size = size; // add header size to offset

    // submit the IP base event

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_IP, HEADERS);

    return CGROUP_SKB_HANDLE(proto);
}

//
// SUPPORTED L3 NETWORK PROTOCOLS (ip, ipv6) HANDLERS
//

// clang-format off

CGROUP_SKB_HANDLE_FUNCTION(proto)
{
    void *dest = NULL;
    u32 prev_hdr_size = neteventctx->md.header_size;
    u32 size = 0;
    u8 next_proto = 0;

    // NOTE: might block IP and IPv6 here if needed (return 0)

    switch (ctx->family) {

        case PF_INET:

            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

            next_proto = nethdrs->iphdrs.iphdr.protocol;

            switch (nethdrs->iphdrs.iphdr.protocol) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = get_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = get_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMP:
                    dest = &nethdrs->protohdrs.icmphdr;
                    size = 0; // will be added later, last function
                    break;
                default:
                    return 1; // other protocols are not an error
            }
            break;

        case PF_INET6:

            // TODO: dual-stack IP implementation unsupported for now
            // https://en.wikipedia.org/wiki/IPv6_transition_mechanism

            if (nethdrs->iphdrs.ipv6hdr.version != 6) // IPv6
                return 1;

            next_proto = nethdrs->iphdrs.ipv6hdr.nexthdr;

            switch (nethdrs->iphdrs.ipv6hdr.nexthdr) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = get_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = get_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMPV6:
                    dest = &nethdrs->protohdrs.icmp6hdr;
                    size = 0; // will be added later, last function
                    break;
                default:
                    return 1; // other protocols are not an error
            }
            break;

        default: // do not handle other protocol families
            return 1;
    }

    if (!dest)
        return 1; // satisfy verifier for clang-12 generated binaries

    neteventctx->md.header_size += size; // add header size to offset

    // load layer 4 protocol headers

    if (size) {
        if (bpf_skb_load_bytes_relative(ctx,
                                        prev_hdr_size,
                                        dest, size,
                                        BPF_HDR_START_NET))
            return 1;
    }

   // call protocol handlers (for more base events to be sent)

    switch (next_proto) {
        case IPPROTO_TCP:
            return CGROUP_SKB_HANDLE(proto_tcp);
        case IPPROTO_UDP:
            return CGROUP_SKB_HANDLE(proto_udp);
        case IPPROTO_ICMP:
            return CGROUP_SKB_HANDLE(proto_icmp);
        case IPPROTO_ICMPV6:
            return CGROUP_SKB_HANDLE(proto_icmpv6);
        default:
            return 1; // shouldn't ever happen here
    }

    // TODO: If cmdline is tracing net_packet_ipv6 only, then the ipv4 packets
    //       shouldn't be added to the pcap file. Filters will have to be
    //       applied to the capture pipeline to obey derived events only
    //       filters + capture.

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_capture(); // capture ipv4/ipv6 only packets

    return 1;
}

// clang-format on

//
// SUPPORTED L4 NETWORK PROTOCOL (tcp, udp, icmp) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp)
{
    // check flag for dynamic header size (TCP: data offset flag)

    if (nethdrs->protohdrs.tcphdr.doff > 5) { // offset flag set
        u32 doff = nethdrs->protohdrs.tcphdr.doff * (32 / 8);
        neteventctx->md.header_size -= get_type_size(struct tcphdr);
        neteventctx->md.header_size += doff;
    }

    // submit TCP base event if needed (only headers)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_TCP, HEADERS);

    // fastpath: return if no other L7 network events

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS) &&
        !should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        goto capture;

    // guess layer 7 protocols

    u16 source = bpf_ntohs(nethdrs->protohdrs.tcphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.tcphdr.dest);

    // guess by src/dst ports

    switch (source < dest ? source : dest) {
        case TCP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_tcp_dns);
    }

    // guess by analyzing payload

    int http_proto = net_l7_is_http(ctx, neteventctx->md.header_size);
    if (http_proto) {
        neteventctx->eventctx.retval |= http_proto;
        return CGROUP_SKB_HANDLE(proto_tcp_http);
    }

    // continue with net_l7_is_protocol_xxx
    // ...

capture:
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP))
        cgroup_skb_capture(); // capture ip or tcp packets

    return 1; // NOTE: might block TCP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp)
{
    // submit UDP base event if needed (only headers)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_UDP, HEADERS);

    // fastpath: return if no other L7 network events

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS) &&
        !should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        goto capture;

    // guess layer 7 protocols

    u16 source = bpf_ntohs(nethdrs->protohdrs.udphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.udphdr.dest);

    // guess by src/dst ports

    switch (source < dest ? source : dest) {
        case UDP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_udp_dns);
    }

    // guess by analyzing payload
    // ...

    // continue with net_l7_is_protocol_xxx
    // ...

capture:
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP))
        cgroup_skb_capture(); // capture ip or udp packets

    return 1; // NOTE: might block UDP here if needed (return 0)
}

// clang-format off
CGROUP_SKB_HANDLE_FUNCTION(proto_icmp)
{
    // submit ICMP base event if needed (full packet)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_ICMP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_ICMP, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_ICMP)) {

        // full icmp header for capture (payload doesn't make much sense)
        neteventctx->md.header_size = ctx->len;
        cgroup_skb_capture(); // capture ip or icmp packets
    }

    return 1; // NOTE: might block ICMP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_icmpv6)
{
    // submit ICMPv6 base event if needed (full packet)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_ICMPV6))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_ICMPV6, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_ICMPV6)) {

        // full icmpv6 header for capture (payload doesn't make much sense)
        neteventctx->md.header_size = ctx->len;
        cgroup_skb_capture(); // capture ip or icmpv6 packets
    }

    return 1; // NOTE: might block ICMPv6 here if needed (return 0)
}

//
// SUPPORTED L7 NETWORK PROTOCOL (dns) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns)
{
    // submit DNS base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_DNS, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS)) {

        // full dns header for capture (payload doesn't make much sense)
        neteventctx->md.header_size = ctx->len;
        cgroup_skb_capture(); // capture dns-tcp, tcp or ip packets
    }

    return 1; // NOTE: might block DNS here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns)
{
    // submit DNS base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_DNS, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS)) {

        // full dns header for capture (payload doesn't make much sense)
        neteventctx->md.header_size = ctx->len;
        cgroup_skb_capture(); // capture dns-udp, udp or ip packets
    }

    return 1; // NOTE: might block DNS here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_http)
{
    // submit HTTP base event if needed (full packet)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_HTTP, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP) ||
        should_submit_net_event(neteventctx, SUB_NET_PACKET_HTTP))
        cgroup_skb_capture(); // capture http-tcp, tcp or ip packets

    // payload here DOES make sense so don't change header_size

    return 1; // NOTE: might block HTTP here if needed (return 0)
}
// clang-format on

#endif
