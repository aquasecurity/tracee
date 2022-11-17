#ifndef __TRACEE_TYPES_H__
#define __TRACEE_TYPES_H__

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
    u32 flags;
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
    bool recompute_scope; // recompute should_trace (new task/context changed/policy changed)
    bool new_task;        // set if this task was started after tracee. Used with new_pid filter
    bool follow;          // set if this task was traced before. Used with the follow filter
    int should_trace;     // last decision of should_trace()
    u8 container_state;   // the state of the container the task resides in
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
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;
    u64 mnt_ns_max;
    u64 mnt_ns_min;
    u64 pid_ns_max;
    u64 pid_ns_min;
    u8 events_to_submit[128]; // use 8*128 bits to describe up to 1024 events
} config_entry_t;

typedef struct event_data {
    event_context_t context;
    struct task_struct *task;
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

typedef struct file_info {
    char pathname[MAX_CACHED_PATH_SIZE];
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_info_t;

typedef struct bpf_attach_key {
    u32 host_tid;
    u32 prog_id;
} bpf_attach_key_t;

typedef struct bpf_attach {
    enum bpf_write_user_e write_user;
} bpf_attach_t;

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

#endif // header