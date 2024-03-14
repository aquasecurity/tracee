#ifndef __MAPS_H__
#define __MAPS_H__

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include <types.h>

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
    TAIL_EXEC_BINPRM1,
    TAIL_EXEC_BINPRM2,
    TAIL_HIDDEN_KERNEL_MODULE_PROC,
    TAIL_HIDDEN_KERNEL_MODULE_KSET,
    TAIL_HIDDEN_KERNEL_MODULE_MOD_TREE,
    TAIL_HIDDEN_KERNEL_MODULE_NEW_MOD_ONLY,
    MAX_TAIL_CALL
};

// kernel config variables
struct kconfig_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} kconfig_map SEC(".maps");

typedef struct kconfig_map kconfig_map_t;

// map cgroup id to container status {EXISTED, CREATED, STARTED}
struct containers_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u8);
} containers_map SEC(".maps");

typedef struct containers_map containers_map_t;

// persist args between function entry and return
struct args_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, args_t);
} args_map SEC(".maps");

typedef struct args_map args_map_t;

// map 32bit to 64bit syscalls
struct sys_32_to_64_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} sys_32_to_64_map SEC(".maps");

typedef struct sys_32_to_64_map sys_32_to_64_map_t;

// holds data for every process
struct proc_info_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 30720);
    __type(key, u32);
    __type(value, proc_info_t);
} proc_info_map SEC(".maps");

typedef struct proc_info_map proc_info_map_t;

// holds data for every task
struct task_info_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, task_info_t);
} task_info_map SEC(".maps");

typedef struct task_info_map task_info_map_t;

// holds the addresses of some kernel symbols
struct ksymbols_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, ksym_name_t);
    __type(value, u64);
} ksymbols_map SEC(".maps");

typedef struct ksymbols_map ksymbols_map_t;

// various configurations
struct config_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, config_entry_t);
} config_map SEC(".maps");

typedef struct config_map config_map_t;

// filter file write captures
struct file_write_path_filter {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, path_filter_t);
} file_write_path_filter SEC(".maps");

typedef struct file_write_path_filter file_write_path_filter_t;

// filter file read captures
struct file_read_path_filter {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, path_filter_t);
} file_read_path_filter SEC(".maps");

typedef struct file_read_path_filter file_read_path_filter_t;

// filter file types
struct file_type_filter {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, file_type_t);
} file_type_filter SEC(".maps");

typedef struct file_type_filter file_type_filter_t;

// network related configurations
struct netconfig_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, netconfig_entry_t);
} netconfig_map SEC(".maps");

typedef struct netconfig_map netconfig_map_t;

// expected addresses of sys call table
struct expected_sys_call_table {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SYS_CALL_TABLE_SIZE);
    __type(key, u32);
    __type(value, syscall_table_entry_t);
} expected_sys_call_table SEC(".maps");

typedef struct expected_sys_call_table expected_sys_call_table_t;

// percpu global buffer variables
struct bufs {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUFFERS);
    __type(key, u32);
    __type(value, buf_t);
} bufs SEC(".maps");

typedef struct bufs bufs_t;

// store programs for tail calls
struct prog_array {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_TAIL_CALL);
    __type(key, u32);
    __type(value, u32);
} prog_array SEC(".maps");

typedef struct prog_array prog_array_t;

// store programs for tail calls
struct prog_array_tp {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_TAIL_CALL);
    __type(key, u32);
    __type(value, u32);
} prog_array_tp SEC(".maps");

typedef struct prog_array_tp prog_array_tp_t;

// store syscall specific programs for tail calls from sys_enter
struct sys_enter_tails {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_tails SEC(".maps");

typedef struct sys_enter_tails sys_enter_tails_t;

// store syscall specific programs for tail calls from sys_exit
struct sys_exit_tails {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_exit_tails SEC(".maps");

typedef struct sys_exit_tails sys_exit_tails_t;

// store program for submitting syscalls from sys_enter
struct sys_enter_submit_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_submit_tail SEC(".maps");

typedef struct sys_enter_submit_tail sys_enter_submit_tail_t;

// store program for submitting syscalls from sys_exit
struct sys_exit_submit_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_exit_submit_tail SEC(".maps");

typedef struct sys_exit_submit_tail sys_exit_submit_tail_t;

// store program for performing syscall tracking logic in sys_enter
struct sys_enter_init_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_init_tail SEC(".maps");

typedef struct sys_enter_init_tail sys_enter_init_tail_t;

// store program for performing syscall tracking logic in sys_exits
struct sys_exit_init_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_exit_init_tail SEC(".maps");

typedef struct sys_exit_init_tail sys_exit_init_tail_t;

// store stack traces
#define MAX_STACK_ADDRESSES 1024 // max amount of diff stack trace addrs to buffer

struct stack_addresses {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_ADDRESSES);
    __type(key, u32);
    __type(value, stack_trace_t); // 1 big byte array of the stack addresses
} stack_addresses SEC(".maps");

typedef struct stack_addresses stack_addresses_t;

// store fds paths by timestamp
struct fd_arg_path_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, fd_arg_path_t);
} fd_arg_path_map SEC(".maps");

typedef struct fd_arg_path_map fd_arg_path_map_t;

// holds bpf prog info
struct bpf_attach_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, bpf_used_helpers_t);
} bpf_attach_map SEC(".maps");

typedef struct bpf_attach_map bpf_attach_map_t;

// temporarily hold bpf_used_helpers_t
struct bpf_attach_tmp_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, bpf_used_helpers_t);
} bpf_attach_tmp_map SEC(".maps");

typedef struct bpf_attach_tmp_map bpf_attach_tmp_map_t;

// store bpf prog aux pointer between bpf_check and security_bpf_prog
struct bpf_prog_load_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, void *);
} bpf_prog_load_map SEC(".maps");

typedef struct bpf_prog_load_map bpf_prog_load_map_t;

// persist event related data
struct event_data_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, event_data_t);
} event_data_map SEC(".maps");

typedef struct event_data_map event_data_map_t;

// signal scratch map
struct signal_data_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, controlplane_signal_t);
} signal_data_map SEC(".maps");

typedef struct signal_data_map signal_data_map_t;

// logs count
struct logs_count {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, bpf_log_t);
    __type(value, bpf_log_count_t);
} logs_count SEC(".maps");

typedef struct logs_count logs_count_t;

// scratch space to avoid allocating stuff on the stack
struct scratch_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, scratch_t);
} scratch_map SEC(".maps");

typedef struct scratch_map scratch_map_t;

// hold file data to decide if should submit file modification event
struct file_modification_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, file_mod_key_t);
    __type(value, s32);
} file_modification_map SEC(".maps");

typedef struct file_modification_map file_modification_map_t;

// store cache for IO operations path
struct io_file_path_cache_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 5);
    __type(key, file_id_t);
    __type(value, path_buf_t);
} io_file_path_cache_map SEC(".maps");

typedef struct io_file_path_cache_map io_file_path_cache_map_t;

// store cache for file ELF type check
struct elf_files_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, file_id_t);
    __type(value, bool);
} elf_files_map SEC(".maps");

typedef struct elf_files_map elf_files_map_t;

//
// versioned maps (map of maps)
//

#define MAX_FILTER_VERSION 64 // max amount of filter versions to track
struct policies_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, policies_config_t);
} policies_config_map SEC(".maps");

typedef struct policies_config_map policies_config_map_t;

// map of policies config maps
struct policies_config_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, policies_config_map_t);
} policies_config_version SEC(".maps");

typedef struct policies_config_version policies_config_version_t;

// filter events by UID prototype, for specific UIDs either by == or !=
struct uid_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, eq_t);
} uid_filter SEC(".maps");

typedef struct uid_filter uid_filter_t;

// map of UID filters maps
struct uid_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, uid_filter_t);
} uid_filter_version SEC(".maps");

typedef struct uid_filter_version uid_filter_version_t;

// filter events by PID
struct pid_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, eq_t);
} pid_filter SEC(".maps");

typedef struct pid_filter pid_filter_t;

// map of PID filters maps
struct pid_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, pid_filter_t);
} pid_filter_version SEC(".maps");

typedef struct pid_filter_version pid_filter_version_t;

// filter events by mount namespace id
struct mnt_ns_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);
    __type(value, eq_t);
} mnt_ns_filter SEC(".maps");

typedef struct mnt_ns_filter mnt_ns_filter_t;

// map of mount namespace filters maps
struct mnt_ns_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, mnt_ns_filter_t);
} mnt_ns_filter_version SEC(".maps");

typedef struct mnt_ns_filter_version mnt_ns_filter_version_t;

// filter events by pid namespace id
struct pid_ns_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);
    __type(value, eq_t);
} pid_ns_filter SEC(".maps");

typedef struct pid_ns_filter pid_ns_filter_t;

// map of pid namespace filters maps
struct pid_ns_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, pid_ns_filter_t);
} pid_ns_filter_version SEC(".maps");

typedef struct pid_ns_filter_version pid_ns_filter_version_t;

// filter events by uts namespace name
struct uts_ns_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, string_filter_t);
    __type(value, eq_t);
} uts_ns_filter SEC(".maps");

typedef struct uts_ns_filter uts_ns_filter_t;

// map of uts namespace filters maps
struct uts_ns_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, uts_ns_filter_t);
} uts_ns_filter_version SEC(".maps");

typedef struct uts_ns_filter_version uts_ns_filter_version_t;

// filter events by command name
struct comm_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, string_filter_t);
    __type(value, eq_t);
} comm_filter SEC(".maps");

typedef struct comm_filter comm_filter_t;

// map of command name filters maps
struct comm_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, comm_filter_t);
} comm_filter_version SEC(".maps");

typedef struct comm_filter_version comm_filter_version_t;

// filter events by cgroup id
struct cgroup_id_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, eq_t);
} cgroup_id_filter SEC(".maps");

typedef struct cgroup_id_filter cgroup_id_filter_t;

// map of cgroup id filters maps
struct cgroup_id_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, cgroup_id_filter_t);
} cgroup_id_filter_version SEC(".maps");

typedef struct cgroup_id_filter_version cgroup_id_filter_version_t;

// filter events by binary path and mount namespace
struct binary_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, binary_t);
    __type(value, eq_t);
} binary_filter SEC(".maps");

typedef struct binary_filter binary_filter_t;

// map of binary filters maps
struct binary_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, binary_filter_t);
} binary_filter_version SEC(".maps");

typedef struct binary_filter_version binary_filter_version_t;

// filter events by the ancestry of the traced process
struct process_tree_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, eq_t);
} process_tree_map SEC(".maps");

typedef struct process_tree_map process_tree_map_t;

// map of process tree maps
struct process_tree_map_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, process_tree_map_t);
} process_tree_map_version SEC(".maps");

typedef struct process_tree_map_version process_tree_map_version_t;

// map to persist event configuration data
struct events_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, event_config_t);
} events_map SEC(".maps");

typedef struct events_map events_map_t;

// map of events maps
struct events_map_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);
    __array(values, events_map_t);
} events_map_version SEC(".maps");

typedef struct events_map_version events_map_version_t;

//
// perf event maps
//

// logs submission
struct logs {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, u32);
} logs SEC(".maps");

typedef struct logs logs_t;

// events submission
struct events {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, u32);
} events SEC(".maps");

typedef struct events events_t;

// file writes events submission
struct file_writes {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, u32);
} file_writes SEC(".maps");

typedef struct file_writes file_writes_t;

// control plane signals submissions
struct signals {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, u32);
} signals SEC(".maps");

typedef struct signals signals_t;

#endif /* __MAPS_H__ */
