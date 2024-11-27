#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <linux/limits.h>
#include <common/consts.h>

typedef struct task_context {
    u64 start_time;               // task's start time
    u64 cgroup_id;                // control group ID
    u32 pid;                      // PID as in the userspace term
    u32 tid;                      // TID as in the userspace term
    u32 ppid;                     // Parent PID as in the userspace term
    u32 host_pid;                 // PID in host pid namespace
    u32 host_tid;                 // TID in host pid namespace
    u32 host_ppid;                // Parent PID in host pid namespace
    u32 uid;                      // task's effective UID
    u32 mnt_id;                   // task's mount namespace ID
    u32 pid_id;                   // task's pid namespace ID
    char comm[TASK_COMM_LEN];     // task's comm
    char uts_name[TASK_COMM_LEN]; // task's uts name
    u32 flags;                    // task's status flags (see context_flags_e)
    u64 leader_start_time;        // task leader's monotonic start time
    u64 parent_start_time;        // parent process task leader's monotonic start time
} task_context_t;

typedef struct event_context {
    u64 ts; // timestamp
    task_context_t task;
    u32 eventid;
    s32 syscall; // syscall that triggered the event
    s64 retval;
    u32 stack_id;
    u16 processor_id; // ID of the processor that processed the event
    u16 policies_version;
    u64 matched_policies;
} event_context_t;

enum event_id_e
{
    // Net events IDs
    NET_PACKET_BASE = 700,
    NET_PACKET_RAW,
    NET_PACKET_IP,
    NET_PACKET_TCP,
    NET_PACKET_UDP,
    NET_PACKET_ICMP,
    NET_PACKET_ICMPV6,
    NET_PACKET_DNS,
    NET_PACKET_HTTP,
    NET_CAPTURE_BASE,
    NET_FLOW_BASE,
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
    SYSCALL_TABLE_CHECK,
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
    PROCESS_EXECUTE_FAILED,
    SECURITY_PATH_NOTIFY,
    SET_FS_PWD,
    SUSPICIOUS_SYSCALL_SOURCE,
    STACK_PIVOT,
    HIDDEN_KERNEL_MODULE_SEEKER,
    MODULE_LOAD,
    MODULE_FREE,
    EXECUTE_FINISHED,
    PROCESS_EXECUTE_FAILED_INTERNAL,
    SECURITY_TASK_SETRLIMIT,
    SECURITY_SETTIME64,
    CHMOD_COMMON,
    MAX_EVENT_ID,
    NO_EVENT_SUBMIT,

    // Test events IDs
    EXEC_TEST = 8000,
    TEST_MISSING_KSYMBOLS,
    TEST_FAILED_ATTACH,
};

enum signal_event_id_e
{
    SIGNAL_CGROUP_MKDIR = 5000,
    SIGNAL_CGROUP_RMDIR,
    SIGNAL_SCHED_PROCESS_FORK,
    SIGNAL_SCHED_PROCESS_EXEC,
    SIGNAL_SCHED_PROCESS_EXIT,
};

typedef struct args {
    unsigned long args[6];
} args_t;

// NOTE: If any fields are added to argument_type_e, the array type_size_table
// (and related defines) must be updated accordingly.
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

typedef struct {
    u64 start;
    u64 end;
} address_range_t;

typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced; // indicates that syscall_data is valid
    u8 container_state;  // the state of the container the task resides in
    address_range_t
        stack; // stack area, only relevant for tasks that aren't group leaders (threads)
} task_info_t;

typedef struct file_id {
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_id_t;

typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    file_id_t id;
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

typedef struct path_buf {
    u8 buf[PATH_MAX];
} path_buf_t;

typedef struct path_filter {
    char path[MAX_PATH_PREF_SIZE];
} path_filter_t;

typedef struct data_filter_key {
    char str[MAX_DATA_FILTER_STR_SIZE];
} data_filter_key_t;

typedef struct data_filter_lpm_key {
    u32 prefix_len;
    char str[MAX_DATA_FILTER_STR_SIZE];
} data_filter_lpm_key_t;

typedef struct string_filter {
    char str[MAX_STR_FILTER_SIZE];
} string_filter_t;

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

typedef struct policy_key {
    u16 version;
    u16 __pad;
    u32 event_id;
} policy_key_t;

typedef struct equality {
    // bitmap indicating which policies have a filter that uses the '=' operator (0 means '!=')
    u64 equals_in_policies;
    // bitmap indicating which policies have a filter that utilize the provided key
    u64 key_used_in_policies;
} eq_t;

typedef struct policies_config {
    // bitmap indicating which policies have the filter enabled
    u64 uid_filter_enabled;
    u64 pid_filter_enabled;
    u64 mnt_ns_filter_enabled;
    u64 pid_ns_filter_enabled;
    u64 uts_ns_filter_enabled;
    u64 comm_filter_enabled;
    u64 cgroup_id_filter_enabled;
    u64 cont_filter_enabled;
    u64 new_cont_filter_enabled;
    u64 new_pid_filter_enabled;
    u64 proc_tree_filter_enabled;
    u64 bin_path_filter_enabled;
    u64 follow_filter_enabled;
    // bitmap indicating whether to match a rule if the key is missing from its filter map
    u64 uid_filter_match_if_key_missing;
    u64 pid_filter_match_if_key_missing;
    u64 mnt_ns_filter_match_if_key_missing;
    u64 pid_ns_filter_match_if_key_missing;
    u64 uts_ns_filter_match_if_key_missing;
    u64 comm_filter_match_if_key_missing;
    u64 cgroup_id_filter_match_if_key_missing;
    u64 cont_filter_match_if_key_missing;
    u64 new_cont_filter_match_if_key_missing;
    u64 new_pid_filter_match_if_key_missing;
    u64 proc_tree_filter_match_if_key_missing;
    u64 bin_path_filter_match_if_key_missing;
    // bitmap with policies that have at least one filter enabled
    u64 enabled_policies;

    // global min max
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;
} policies_config_t;

typedef struct config_entry {
    u32 tracee_pid;
    u32 options;
    u32 cgroup_v1_hid;
    u16 padding; // free for further use
    u16 policies_version;
    policies_config_t policies_config;
} config_entry_t;

typedef struct string_filter_config {
    u64 prefix_enabled;
    u64 suffix_enabled;
    u64 exact_enabled;
    u64 prefix_match_if_key_missing;
    u64 suffix_match_if_key_missing;
    u64 exact_match_if_key_missing;
} string_filter_config_t;

typedef struct data_filter_config {
    string_filter_config_t string;
    // other types of filters
} data_filter_config_t;

typedef struct event_config {
    u64 submit_for_policies;
    u64 field_types;
    data_filter_config_t data_filter;
} event_config_t;

enum capture_options_e
{
    NET_CAP_OPT_FILTERED = (1 << 0), // pcap should obey event filters
};

typedef struct netconfig_entry {
    u32 capture_options; // bitmask of capture options (pcap)
    u32 capture_length;  // amount of network packet payload to capture (pcap)
} netconfig_entry_t;

typedef struct syscall_table_entry {
    u64 address;
} syscall_table_entry_t;

typedef struct args_buffer {
    u8 argnum;
    char args[ARGS_BUF_SIZE];
    u16 offset;
    u16 args_offset[MAX_ARGS];
} args_buffer_t;

typedef struct event_data {
    event_context_t context;
    args_buffer_t args_buf;
    struct task_struct *task;
    event_config_t config;
    policies_config_t policies_config;
} event_data_t;

// A control plane signal - sent to indicate some critical event which should be processed
// with priority.
//
// Signals currently consist of shortened events sent only with their arguments.
// As such, they consist of an event id and an argument buffer.
// If we ever require a signal independent of an event, the event_id field should change
// accordingly.
typedef struct controlplane_signal {
    u32 event_id;
    args_buffer_t args_buf;
} controlplane_signal_t;

#define MAX_EVENT_SIZE  sizeof(event_context_t) + sizeof(u8) + ARGS_BUF_SIZE
#define MAX_SIGNAL_SIZE sizeof(u32) + sizeof(u8) + ARGS_BUF_SIZE

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

    // hidden kernel module functions
    BPF_LOG_ID_HID_KER_MOD,

    // find vma not supported
    BPF_LOG_FIND_VMA_UNSUPPORTED,
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
    proc_info_t *proc_info;
    event_data_t *event;
    u32 scratch_idx;
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
    bool unused; // Empty struct yields an error from the verifier: "Invalid argument(-22)""
} kernel_module_t;

typedef struct kernel_new_mod {
    u64 insert_time;
    u64 last_seen_time;
} kernel_new_mod_t;

typedef struct kernel_deleted_mod {
    u64 deleted_time;
} kernel_deleted_mod_t;

typedef struct rb_node_stack {
    struct rb_node *node;
} rb_node_t;

#define MODULE_SRCVERSION_MAX_LENGTH 25

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

#define MAX_STACK_DEPTH 20 // max depth of each stack trace to track

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
typedef u32 file_type_t;

struct sys_exit_tracepoint_args {
    u64 __pad;
    int __syscall_nr;
    long ret;
};

// key for the syscall source map
typedef struct {
    u32 syscall;
    u32 tgid;
    u64 tgid_start_time;
    u64 vma_addr;
} syscall_source_key_t;

#endif
