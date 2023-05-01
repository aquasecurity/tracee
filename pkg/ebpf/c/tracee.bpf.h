#ifndef __TRACEE_BPF_H__
#define __TRACEE_BPF_H__

#ifndef CORE
    #include <missing_noncore_definitions.h>
#else
    #include <missing_definitions.h>
    #include <vmlinux.h>
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "types.h"
#include "common/network.h"

static __always_inline int send_socket_dup(program_data_t *p, u64 oldfd, u64 newfd);

// Populate all the modules to an efficient query-able hash map.
static __always_inline bool init_shown_modules();

static __always_inline bool is_hidden(u64 mod);

static __always_inline bool find_modules_from_module_kset_list(program_data_t *p);

#ifdef CORE // in non CORE builds it's already defined
static __always_inline struct latch_tree_node *__lt_from_rb(struct rb_node *node, int idx);
#endif

static __always_inline bool walk_mod_tree(program_data_t *p, struct rb_node *root, int idx);

static __always_inline bool find_modules_from_mod_tree(program_data_t *p);

static __always_inline bool check_is_proc_modules_hooked(program_data_t *p);

static __always_inline bool kern_ver_below_min_lkm(struct pt_regs *ctx);

static __always_inline struct trace_kprobe *get_trace_kprobe_from_trace_probe(void *tracep);

static __always_inline struct trace_uprobe *get_trace_uprobe_from_trace_probe(void *tracep);

// This function returns a pointer to struct trace_probe from struct trace_event_call.
static __always_inline void *get_trace_probe_from_trace_event_call(struct trace_event_call *call);

// Inspired by bpf_get_perf_event_info() kernel func.
// https://elixir.bootlin.com/linux/v5.19.2/source/kernel/trace/bpf_trace.c#L2123
static __always_inline int
send_bpf_attach(program_data_t *p, struct file *bpf_prog_file, struct file *perf_event_file);

static __always_inline u32 tail_call_send_bin(void *ctx,
                                              program_data_t *p,
                                              bin_args_t *bin_args,
                                              int tail_call);

static __always_inline u32 send_bin_helper(void *ctx, void *prog_array, int tail_call);

static __always_inline int
submit_magic_write(program_data_t *p, file_info_t *file_info, io_data_t io_data, u32 bytes_written);

static __always_inline bool should_submit_io_event(u32 event_id, program_data_t *p);

/** do_file_io_operation - generic file IO (read and write) event creator.
 *
 * @ctx:            the state of the registers prior the hook.
 * @event_id:       the ID of the event to be created.
 * @tail_call_id:   the ID of the tail call to be called before function return.
 * @is_read:        true if the operation is read. False if write.
 * @is_buf:         true if the non-file side of the operation is a buffer. False if io_vector.
 */
static __always_inline int
do_file_io_operation(struct pt_regs *ctx, u32 event_id, u32 tail_call_id, bool is_read, bool is_buf);

// Capture file write
// Will only capture if:
// 1. File write capture was configured
// 2. File matches the filters given
static __always_inline int capture_file_write(struct pt_regs *ctx, u32 event_id);

// Check (CORE || (!CORE && kernel >= 5.7)) to compile successfully.
// (compiler will try to compile the func even if no execution path leads to it).
#if defined(CORE) || (!defined(CORE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)))
static __always_inline int do_check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd);
#endif

static __always_inline int check_bpf_link(program_data_t *p, union bpf_attr *attr, int cmd);

// arm_kprobe can't be hooked in arm64 architecture, use enable logic instead
static __always_inline int arm_kprobe_handler(struct pt_regs *ctx);

static __always_inline int handle_bpf_helper_func_id(u32 host_tid, int func_id);

static __always_inline struct pipe_buffer *get_last_write_pipe_buffer(struct pipe_inode_info *pipe);

static __always_inline int common_utimes(struct pt_regs *ctx);

static __always_inline int common_file_modification_ent(struct pt_regs *ctx);

static __always_inline int common_file_modification_ret(struct pt_regs *ctx);

// Network Packets (works from ~5.2 and beyond)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 0) || defined(CORE)) || defined(RHEL_RELEASE_CODE)

// To track ingress/egress traffic we always need to link a flow to its related
// task (particularly when hooking ingress skb bpf programs, where the current
// task is typically a kernel thread).

// In older kernels, managing cgroup skb programs can be more difficult due to
// the lack of bpf helpers and buggy/incomplete verifier. To deal with this,
// this approach uses a technique of kprobing the function responsible for
// calling the cgroup/skb programs.

// Tracee utilizes a technique of kprobing the function responsible for calling
// the cgroup/skb programs in order to perform the tasks which cgroup skb
// programs would usually accomplish. Through this method, all the data needed
// by the cgroup/skb programs is already stored in a map.

// Unfortunately this approach has some cons: the kprobe to cgroup/skb execution
// flow does not have preemption disabled, so the map used in between all the
// hooks need to use as a key something that is available to all the hooks
// context (the packet contents themselves: e.g. L3 header fields).

// At the end, the logic is simple: every time a socket is created an inode is
// also created. The task owning the socket is indexed by the socket inode so
// everytime this socket is used we know which task it belongs to (specially
// during ingress hook, executed from the softirq context within a kthread).

//
// network helper functions
//

static __always_inline bool is_family_supported(struct socket *sock);

static __always_inline bool is_socket_supported(struct socket *sock);

//
// Support functions for network code
//

static __always_inline u64 sizeof_net_event_context_t(void);

static __always_inline void set_net_task_context(event_data_t *event, net_task_context_t *netctx);

static __always_inline int should_submit_net_event(net_event_context_t *neteventctx,
                                                   net_packet_t packet_type);

static __always_inline int should_capture_net_event(net_event_context_t *neteventctx,
                                                    net_packet_t packet_type);

static __always_inline u32 cgroup_skb_submit(void *map,
                                             struct __sk_buff *ctx,
                                             net_event_context_t *neteventctx,
                                             u32 event_type,
                                             u32 size);


static __always_inline u32 cgroup_skb_capture_event(struct __sk_buff *ctx,
                                                    net_event_context_t *neteventctx,
                                                    u32 event_type);

static __always_inline u32 update_net_inodemap(struct socket *sock, event_data_t *event);

static __always_inline u32 cgroup_skb_generic(struct __sk_buff *ctx, void *cgrpctxmap);

static __always_inline int net_l7_is_http(struct __sk_buff *skb, u32 l7_off);

#endif // Network Packets

#endif
