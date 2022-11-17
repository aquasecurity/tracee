#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                       \
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

// EBPF MAPS DECLARATIONS --------------------------------------------------------------------------

// clang-format off
BPF_HASH(kconfig_map, u32, u32, 10240);                            // kernel config variables
BPF_HASH(interpreter_map, u32, file_info_t, 10240);                // interpreter file used for each process
BPF_HASH(containers_map, u32, u8, 10240);                          // map cgroup id to container status {EXISTED, CREATED, STARTED}
BPF_HASH(args_map, u64, args_t, 1024);                             // persist args between function entry and return
BPF_HASH(uid_filter, u32, u32, 256);                               // filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, u32, 256);                               // filter events by PID
BPF_HASH(mnt_ns_filter, u64, u32, 256);                            // filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, u32, 256);                            // filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, u32, 256);                // filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, u32, 256);                  // filter events by command name
BPF_HASH(cgroup_id_filter, u32, u32, 256);                         // filter events by cgroup id
BPF_HASH(bin_args_map, u64, bin_args_t, 256);                      // persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32, 1024);                        // map 32bit to 64bit syscalls
BPF_HASH(params_types_map, u32, u64, 1024);                        // encoded parameters types for event
BPF_HASH(process_tree_map, u32, u32, 10240);                       // filter events by the ancestry of the traced process
BPF_LRU_HASH(task_info_map, u32, task_info_t, 10240);              // holds data for every task
BPF_HASH(network_config, u32, int, 1024);                          // holds the network config for each iface
BPF_HASH(ksymbols_map, ksym_name_t, u64, 1024);                    // holds the addresses of some kernel symbols
BPF_HASH(syscalls_to_check_map, int, u64, 256);                    // syscalls to discover
BPF_LRU_HASH(sock_ctx_map, u64, net_ctx_ext_t, 10240);             // socket address to process context
BPF_LRU_HASH(network_map, net_id_t, net_ctx_t, 10240);             // network identifier to process context
BPF_ARRAY(config_map, config_entry_t, 1);                          // various configurations
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
// clang-format on

// EBPF PERF BUFFERS -------------------------------------------------------------------------------

BPF_PERF_OUTPUT(events, 1024);      // events submission
BPF_PERF_OUTPUT(file_writes, 1024); // file writes events submission
BPF_PERF_OUTPUT(net_events, 1024);  // network events submission