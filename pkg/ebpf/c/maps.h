#ifndef __MAPS_H__
#define __MAPS_H__

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include <types.h>

#define MAX_STACK_ADDRESSES 1024 // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH     20   // max depth of each stack trace to track

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_MAP_NO_KEY(_name, _type, _value_type, _max_entries)                                    \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
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

#define BPF_QUEUE(_name, _value_type, _max_entries)                                                \
    BPF_MAP_NO_KEY(_name, BPF_MAP_TYPE_QUEUE, _value_type, _max_entries)

#define BPF_STACK(_name, _value_type, _max_entries)                                                \
    BPF_MAP_NO_KEY(_name, BPF_MAP_TYPE_STACK, _value_type, _max_entries)

// stack traces: the value is 1 big byte array of the stack addresses
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries)                                                       \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

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
    MAX_TAIL_CALL
};

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
BPF_HASH(events_map, u32, event_config_t, MAX_EVENT_ID);           // map to persist event configuration data
BPF_HASH(sys_32_to_64_map, u32, u32, 1024);                        // map 32bit to 64bit syscalls
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
BPF_LRU_HASH(bpf_attach_map, u32, bpf_used_helpers_t, 1024);       // holds bpf prog info
BPF_LRU_HASH(bpf_attach_tmp_map, u32, bpf_used_helpers_t, 1024);   // temporarily hold bpf_used_helpers_t
BPF_LRU_HASH(bpf_prog_load_map, u32, void *, 1024);                // store bpf prog aux pointer between bpf_check and security_bpf_prog
BPF_PERCPU_ARRAY(event_data_map, event_data_t, 1);                 // persist event related data
BPF_HASH(logs_count, bpf_log_t, bpf_log_count_t, 4096);            // logs count
BPF_PERCPU_ARRAY(scratch_map, scratch_t, 1);                       // scratch space to avoid allocating stuff on the stack
BPF_LRU_HASH(file_modification_map, file_mod_key_t, int, 10240);   // hold file data to decide if should submit file modification event

// clang-format on

BPF_PERF_OUTPUT(logs, 1024);        // logs submission
BPF_PERF_OUTPUT(events, 1024);      // events submission
BPF_PERF_OUTPUT(file_writes, 1024); // file writes events submission

#endif /* __MAPS_H__ */
