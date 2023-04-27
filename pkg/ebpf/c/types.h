#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <common/consts.h>

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
    s32 syscall; // The syscall which triggered the event
    u64 matched_policies;
    s64 retval;
    u32 stack_id;
    u16 processor_id; // The ID of the processor which processed the event
    u8 argnum;
} event_context_t;

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
    VFS_UTIMES,
    DO_TRUNCATE,
    FILE_MODIFICATION,
    INOTIFY_WATCH,
    SECURITY_BPF_PROG,
    PROCESS_EXECUTION_FAILED,
    HIDDEN_KERNEL_MODULE_SEEKER,
    MAX_EVENT_ID,
};

typedef struct args {
    unsigned long args[6];
} args_t;

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
    TIMESPEC_T,
    TYPE_MAX = 255UL
};

enum internal_hook_e
{
    EXEC_BINPRM = 80000,
};

enum mem_prot_alert_e
{
    ALERT_MMAP_W_X = 1,
    ALERT_MPROT_X_ADD,
    ALERT_MPROT_W_ADD,
    ALERT_MPROT_W_REM
};

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

#define MAX_CACHED_PATH_SIZE 64

typedef struct fd_arg_path {
    char path[MAX_CACHED_PATH_SIZE];
} fd_arg_path_t;

// Flags in each task's context
enum context_flags_e
{
    CONTAINER_STARTED_FLAG = (1 << 0), // mark the task's container have started
    IS_COMPAT_FLAG = (1 << 1)          // is the task running in compatible mode
};

enum container_state_e
{
    CONTAINER_UNKNOWN = 0, // mark that container state is unknown
    CONTAINER_EXISTED,     // container existed before tracee was started
    CONTAINER_CREATED,     // new cgroup path created
    CONTAINER_STARTED      // a process in the cgroup executed a new binary
};

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

typedef struct binary_filter {
    char str[MAX_BIN_PATH_SIZE];
} binary_filter_t;

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

typedef struct equality {
    // bitmask with scopes on which a equal '=' filter is set
    // its bit value will depend on the filter's equality precedence order
    u64 equal_in_scopes;
    // bitmask with scopes on which a filter equality is set
    u64 equality_set_in_scopes;
} eq_t;

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

typedef struct event_config {
    u64 submit_for_policies;
    u64 param_types;
} event_config_t;

enum capture_options_e
{
    NET_CAP_OPT_FILTERED = (1 << 0), // pcap should obey event filters
};

typedef struct netconfig_entry {
    u32 capture_options; // bitmask of capture options (pcap)
    u32 capture_length;  // amount of network packet payload to capture (pcap)
} netconfig_entry_t;

typedef struct event_data {
    event_context_t context;
    char args[ARGS_BUF_SIZE];
    u32 buf_off;
    struct task_struct *task;
    u64 param_types;
} event_data_t;

#define MAX_EVENT_SIZE sizeof(event_context_t) + ARGS_BUF_SIZE

#define BPF_MAX_LOG_FILE_LEN 72

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

typedef struct kernel_mod {
    bool seen_proc_modules;
    bool seen_modules_list;
} kernel_module_t;

typedef struct rb_node_stack {
    struct rb_node *node;
} rb_node_t;

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

// this struct is used to encode which helpers are used in bpf program.
// it is an array of 4 u64 values - 256 bits.
// there are currently 212 bpf helper functions
// (https://elixir.bootlin.com/linux/v6.2.6/source/include/uapi/linux/bpf.h#L5488). the helpers IDs
// start from 0 and continue in a sequence. the encoding is very simple - a bit is turned on if we
// see the corresponding helper ID being used.
#define MAX_NUM_OF_HELPERS   256
#define SIZE_OF_HELPER_ELEM  64
#define NUM_OF_HELPERS_ELEMS MAX_NUM_OF_HELPERS / SIZE_OF_HELPER_ELEM
typedef struct bpf_used_helpers {
    u64 helpers[NUM_OF_HELPERS_ELEMS];
} bpf_used_helpers_t;

typedef struct file_mod_key {
    u32 host_pid;
    dev_t device;
    unsigned long inode;
} file_mod_key_t;

enum file_modification_op
{
    FILE_MODIFICATION_SUBMIT = 0,
    FILE_MODIFICATION_DONE,
};

#endif
