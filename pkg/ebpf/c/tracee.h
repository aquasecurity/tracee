#ifndef __TRACEE_H__
#define __TRACEE_H__

#include <common/common.h>
#include <common/network.h>

statfunc bool kern_ver_below_min_lkm(struct pt_regs *);

// TODO: related to network

statfunc bool is_family_supported(struct socket *);
statfunc bool is_socket_supported(struct socket *);
statfunc u64 sizeof_net_event_context_t(void);
statfunc void set_net_task_context(event_data_t *, net_task_context_t *);
statfunc enum event_id_e net_packet_to_net_event(net_packet_t);
statfunc u64 should_submit_net_event(net_event_context_t *, net_packet_t);
statfunc bool should_submit_flow_event(net_event_context_t *);
statfunc u64 should_capture_net_event(net_event_context_t *, net_packet_t);
statfunc u32 cgroup_skb_generic(struct __sk_buff *, void *);
statfunc int net_l7_is_http(struct __sk_buff *, u32);
statfunc u32 update_net_inodemap(struct socket *, event_data_t *);
statfunc int send_socket_dup(program_data_t *, u64, u64);
statfunc u32 cgroup_skb_submit(void *, struct __sk_buff *, net_event_context_t *, u32, u32);
statfunc u32 cgroup_skb_capture_event(struct __sk_buff *, net_event_context_t *, u32);

// TODO: related to vfs

statfunc int common_utimes(struct pt_regs *);
statfunc int common_file_modification_ent(struct pt_regs *);
statfunc int common_file_modification_ret(struct pt_regs *);

// TODO: related to kernel modules

statfunc int init_shown_modules();
statfunc int is_hidden(u64);
statfunc int find_modules_from_module_kset_list(program_data_t *);
statfunc struct latch_tree_node *__lt_from_rb(struct rb_node *, int);
statfunc int walk_mod_tree(program_data_t *p, struct rb_node *, int);
statfunc int find_modules_from_mod_tree(program_data_t *);
statfunc int check_is_proc_modules_hooked(program_data_t *);

// TODO: related to bpf tracing

statfunc int send_bpf_attach(program_data_t *, struct bpf_prog *, void *, u64, int);
statfunc int check_bpf_link(program_data_t *, union bpf_attr *, int);
statfunc int handle_bpf_helper_func_id(u32, int);
statfunc struct trace_kprobe *get_trace_kprobe_from_trace_probe(void *);
statfunc struct trace_uprobe *get_trace_uprobe_from_trace_probe(void *);
statfunc void *get_trace_probe_from_trace_event_call(struct trace_event_call *);
statfunc int arm_kprobe_handler(struct pt_regs *);

// TODO: related to file capturing

statfunc u32 tail_call_send_bin(void *, program_data_t *, bin_args_t *, int);
statfunc u32 send_bin_helper(void *, void *, int);
statfunc int submit_magic_write(program_data_t *, file_info_t *, io_data_t, u32);
statfunc bool should_submit_io_event(u32, program_data_t *);
statfunc int do_file_io_operation(struct pt_regs *, u32, u32, bool, bool);
statfunc void extract_vfs_ret_io_data(struct pt_regs *, args_t *, io_data_t *, bool);
statfunc bool filter_file_write_capture(program_data_t *, struct file *, io_data_t, off_t);
statfunc int capture_file_write(struct pt_regs *, u32, bool);
statfunc bool filter_file_read_capture(program_data_t *, struct file *, io_data_t, off_t);
statfunc int capture_file_read(struct pt_regs *, u32, bool);
statfunc struct pipe_buffer *get_last_write_pipe_buffer(struct pipe_inode_info *);

#endif
