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

#define BPF_MAP_INNER(_name, _type, _key_type, _value_type, _max_entries)                          \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_HASH_OUTER(_name, _inner_map, _max_entries)                                            \
    struct {                                                                                       \
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);                                                   \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, u16);                                                                          \
        __array(values, typeof(_inner_map));                                                       \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                                      \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_HASH_INNER(_name, _key_type, _value_type, _max_entries)                                \
    BPF_MAP_INNER(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

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
    TAIL_HIDDEN_KERNEL_MODULE_NEW_MOD_ONLY,
    MAX_TAIL_CALL
};

// clang-format off

BPF_HASH(kconfig_map, u32, u32, 10240);                            // kernel config variables
BPF_HASH(containers_map, u32, u8, 10240);                          // map cgroup id to container status {EXISTED, CREATED, STARTED}
BPF_HASH(args_map, u64, args_t, 1024);                             // persist args between function entry and return

// versioned maps
BPF_HASH_INNER(uid_filter, u32, eq_t, 256);                        // filter events by UID prototype, for specific UIDs either by == or !=
BPF_HASH_OUTER(uid_filter_version, uid_filter, 64);                // map of UID filters maps
BPF_HASH_INNER(pid_filter, u32, eq_t, 256);                        // filter events by PID prototype
BPF_HASH_OUTER(pid_filter_version, pid_filter, 64);                // map of PID filters maps
BPF_HASH_INNER(mnt_ns_filter, u64, eq_t, 256);                     // filter events by mount namespace id prototype
BPF_HASH_OUTER(mnt_ns_filter_version, mnt_ns_filter, 64);          // map of mount namespace filters maps
BPF_HASH_INNER(pid_ns_filter, u64, eq_t, 256);                     // filter events by pid namespace id prototype
BPF_HASH_OUTER(pid_ns_filter_version, pid_ns_filter, 64);          // map of pid namespace filters maps
BPF_HASH_INNER(uts_ns_filter, string_filter_t, eq_t, 256);         // filter events by uts namespace name prototype
BPF_HASH_OUTER(uts_ns_filter_version, uts_ns_filter, 64);          // map of uts namespace filters maps
BPF_HASH_INNER(comm_filter, string_filter_t, eq_t, 256);           // filter events by command name prototype
BPF_HASH_OUTER(comm_filter_version, comm_filter, 64);              // map of command name filters maps
BPF_HASH_INNER(cgroup_id_filter, u32, eq_t, 256);                  // filter events by cgroup id prototype
BPF_HASH_OUTER(cgroup_id_filter_version, cgroup_id_filter, 64);    // map of cgroup id filters maps
BPF_HASH_INNER(binary_filter, binary_t, eq_t, 256);                // filter events by binary path and mount namespace prototype
BPF_HASH_OUTER(binary_filter_version, binary_filter, 64);          // map of binary filters maps
BPF_HASH_INNER(process_tree_map, u32, eq_t, 10240);                // filter events by the ancestry of the traced process
BPF_HASH_OUTER(process_tree_map_version, process_tree_map, 64);    // map of process tree maps
BPF_HASH_INNER(events_map, u32, event_config_t, MAX_EVENT_ID);     // map to persist event configuration data
BPF_HASH_OUTER(events_map_version, events_map, 64);                // map of events maps

BPF_HASH(sys_32_to_64_map, u32, u32, 1024);                        // map 32bit to 64bit syscalls
BPF_LRU_HASH(proc_info_map, u32, proc_info_t, 10240);              // holds data for every process
BPF_LRU_HASH(task_info_map, u32, task_info_t, 10240);              // holds data for every task
BPF_HASH(ksymbols_map, ksym_name_t, u64, 1024);                    // holds the addresses of some kernel symbols
BPF_ARRAY(config_map, config_entry_t, 1);                          // various configurations
BPF_ARRAY(file_write_path_filter, path_filter_t, 3);               // filter file write captures
BPF_ARRAY(file_read_path_filter, path_filter_t, 3);                // filter file read captures
BPF_ARRAY(file_type_filter, file_type_filter_t, 2);                // filter file types
BPF_ARRAY(netconfig_map, netconfig_entry_t, 1);                    // network related configurations
BPF_ARRAY(expected_sys_call_table, syscall_table_entry_t, MAX_SYS_CALL_TABLE_SIZE);    // expected addresses of sys call table
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
BPF_LRU_HASH(fd_arg_path_map, u64, fd_arg_path_t, 1024);           // store fds paths by timestamp
BPF_LRU_HASH(bpf_attach_map, u32, bpf_used_helpers_t, 1024);       // holds bpf prog info
BPF_LRU_HASH(bpf_attach_tmp_map, u32, bpf_used_helpers_t, 1024);   // temporarily hold bpf_used_helpers_t
BPF_LRU_HASH(bpf_prog_load_map, u32, void *, 1024);                // store bpf prog aux pointer between bpf_check and security_bpf_prog
BPF_PERCPU_ARRAY(event_data_map, event_data_t, 1);                 // persist event related data
BPF_PERCPU_ARRAY(signal_data_map, controlplane_signal_t, 1);       // signal scratch map
BPF_HASH(logs_count, bpf_log_t, bpf_log_count_t, 4096);            // logs count
BPF_PERCPU_ARRAY(scratch_map, scratch_t, 1);                       // scratch space to avoid allocating stuff on the stack
BPF_LRU_HASH(file_modification_map, file_mod_key_t, int, 10240);   // hold file data to decide if should submit file modification event
BPF_LRU_HASH(io_file_path_cache_map, file_id_t, path_buf_t, 5);    // store cache for IO operations path
BPF_LRU_HASH(elf_files_map, file_id_t, bool, 64);                  // store cache for file ELF type check

// clang-format on

BPF_PERF_OUTPUT(logs, 1024);        // logs submission
BPF_PERF_OUTPUT(events, 1024);      // events submission
BPF_PERF_OUTPUT(file_writes, 1024); // file writes events submission
BPF_PERF_OUTPUT(signals, 1024);     // control plane signals submissions

#endif /* __MAPS_H__ */
