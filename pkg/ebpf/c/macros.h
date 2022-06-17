#include <bpf_tracing.h>

#if defined(bpf_target_x86)
    #define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
    #define PT_REGS_PARM6(x) ((x)->regs[5])
#endif

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

enum bpf_config_e
{
    CONFIG_TRACEE_PID,
    CONFIG_OPTIONS,
    CONFIG_FILTERS,
    CONFIG_CGROUP_V1_HID
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

#define MAX_STR_ARR_ELEM      40 // TODO: turn this into global variables set w/ libbpfgo
#define MAX_ARGS_STR_ARR_ELEM 15
#define MAX_PATH_PREF_SIZE    64
#define MAX_PATH_COMPONENTS   20
#define MAX_BIN_CHUNKS        110

#define IOCTL_FETCH_SYSCALLS            (1 << 0) // bit wise flags
#define IOCTL_HOOKED_SEQ_OPS            (1 << 1)
#define NUMBER_OF_SYSCALLS_TO_CHECK_X86 18
#define NUMBER_OF_SYSCALLS_TO_CHECK_ARM 14

#define MAX_CACHED_PATH_SIZE 64

// EBPF KCONFIGS -----------------------------------------------------------------------------------

#define get_kconfig(x) get_kconfig_val(x)

enum kconfig_key_e
{
    ARCH_HAS_SYSCALL_WRAPPER = 1000U
};

// EBPF MACRO HELPERS ------------------------------------------------------------------------------

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
