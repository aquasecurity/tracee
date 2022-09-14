#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef signed char __s8;
typedef __s8 s8;
typedef s8 int8_t;

typedef short int __s16;
typedef __s16 s16;
typedef s16 int16_t;

typedef int __s32;
typedef __s32 s32;
typedef s32 int32_t;

typedef long long int __s64;
typedef __s64 s64;
typedef s64 int64_t;

typedef unsigned char __u8;
typedef __u8 u8;
typedef u8 uint8_t;
typedef u8 u_int8_t;

typedef short unsigned int __u16;
typedef __u16 u16;
typedef __u16 __le16;
typedef __u16 __be16;
typedef u16 uint16_t;
typedef u16 u_int16_t;

typedef unsigned int __u32;
typedef unsigned int uint;
typedef __u32 u32;
typedef __u32 int32;
typedef __u32 __be32;
typedef u32 uint32_t;
typedef u32 u_int32_t;

typedef long long unsigned int __u64;
typedef __u64 u64;
typedef __u64 __le64;
typedef __u64 __be64;
typedef u64 uint64_t;
typedef u64 u_int64_t;

typedef long int __kernel_long_t;
typedef unsigned int __kernel_mode_t;
typedef __kernel_mode_t mode_t;
typedef __kernel_long_t __kernel_off_t;
typedef __kernel_off_t off_t;

typedef long unsigned int __kernel_ulong_t;

typedef _Bool bool;

enum
{
    false = 0,
    true = 1,
};

#if defined(__TARGET_ARCH_x86)

struct thread_info {
    u32 status;
};

struct pt_regs {
    long unsigned int r15;
    long unsigned int r14;
    long unsigned int r13;
    long unsigned int r12;
    long unsigned int bp;
    long unsigned int bx;
    long unsigned int r11;
    long unsigned int r10;
    long unsigned int r9;
    long unsigned int r8;
    long unsigned int ax;
    long unsigned int cx;
    long unsigned int dx;
    long unsigned int si;
    long unsigned int di;
    long unsigned int orig_ax;
    long unsigned int ip;
    long unsigned int cs;
    long unsigned int flags;
    long unsigned int sp;
    long unsigned int ss;
};

#elif defined(__TARGET_ARCH_arm64)

struct thread_info {
    long unsigned int flags;
};

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            u64 regs[31];
            u64 sp;
            u64 pc;
            u64 pstate;
        };
    };
    u64 orig_x0;
    s32 syscallno;
    u32 unused2;
    u64 orig_addr_limit;
    u64 pmr_save;
    u64 stackframe[2];
    u64 lockdep_hardirqs;
    u64 exit_rcu;
};

#endif

// common to all architectures

enum
{
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
    BPF_F_LOCK = 4,
};

enum
{
    BPF_F_USER_STACK = 256,
};

enum
{
    BPF_F_CURRENT_CPU = 4294967295,
};

enum
{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECV = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_TIME_WAIT = 6,
    TCP_CLOSE = 7,
    TCP_CLOSE_WAIT = 8,
    TCP_LAST_ACK = 9,
    TCP_LISTEN = 10,
    TCP_CLOSING = 11,
    TCP_NEW_SYN_RECV = 12,
    TCP_MAX_STATES = 13,
};

enum sock_type
{
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
    SOCK_RDM = 4,
    SOCK_SEQPACKET = 5,
    SOCK_DCCP = 6,
    SOCK_PACKET = 10,
};

enum
{
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_MTP = 92,
    IPPROTO_BEETPH = 94,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_MPLS = 137,
    IPPROTO_ETHERNET = 143,
    IPPROTO_RAW = 255,
    IPPROTO_MPTCP = 262,
    IPPROTO_MAX = 263,
};

enum
{
    TCPF_ESTABLISHED = 2,
    TCPF_SYN_SENT = 4,
    TCPF_FIN_WAIT1 = 16,
    TCPF_FIN_WAIT2 = 32,
    TCPF_TIME_WAIT = 64,
    TCPF_CLOSE = 128,
    TCPF_CLOSE_WAIT = 256,
    TCPF_LAST_ACK = 512,
    TCPF_LISTEN = 1024,
    TCPF_CLOSING = 2048,
    TCPF_NEW_SYN_RECV = 4096,
};

struct bpf_raw_tracepoint_args {
    __u64 args[0];
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

typedef int __kernel_pid_t;

typedef __kernel_pid_t pid_t;

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_size_t size_t;

typedef unsigned int __kernel_uid32_t;

typedef __kernel_uid32_t uid_t;

typedef struct {
    uid_t val;
} kuid_t;

struct task_struct {
    struct thread_info thread_info;
    unsigned int flags;
    struct mm_struct *mm;
    int exit_code;
    pid_t pid;
    pid_t tgid;
    struct task_struct *real_parent;
    struct task_struct *group_leader;
    struct pid *thread_pid;
    struct list_head thread_group;
    u64 start_time;
    const struct cred *real_cred;
    char comm[16];
    struct files_struct *files;
    struct nsproxy *nsproxy;
    struct css_set *cgroups;
    struct signal_struct *signal;
    void *stack;
};

typedef struct {
    int counter;
} atomic_t;

struct signal_struct {
    atomic_t live;
};

struct vm_area_struct {
    long unsigned int vm_flags;
    struct file *vm_file;
};

typedef unsigned int __kernel_gid32_t;

typedef __kernel_gid32_t gid_t;

typedef struct {
    gid_t val;
} kgid_t;

struct kernel_cap_struct {
    __u32 cap[2];
};

typedef struct kernel_cap_struct kernel_cap_t;

struct cred {
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
    unsigned int securebits;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    kernel_cap_t cap_ambient;
    struct user_namespace *user_ns;
};

struct nsproxy {
    struct uts_namespace *uts_ns;
    struct ipc_namespace *ipc_ns;
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns_for_children;
    struct net *net_ns;
    struct cgroup_namespace *cgroup_ns;
};

struct ns_common {
    unsigned int inum;
};

struct pid_namespace {
    unsigned int level;
    struct ns_common ns;
};

struct upid {
    int nr;
    struct pid_namespace *ns;
};

struct pid {
    unsigned int level;
    struct upid numbers[1];
};

struct mnt_namespace {
    struct ns_common ns;
};

struct new_utsname {
    char nodename[65];
};

struct uts_namespace {
    struct new_utsname name;
    struct ns_common ns;
};

struct css_set {
    struct cgroup_subsys_state *subsys[12];
};

struct percpu_ref {
    long unsigned int percpu_count_ptr;
    struct percpu_ref_data *data;
};

struct cgroup_subsys_state {
    struct cgroup *cgroup;
};

struct timer_list {
    struct hlist_node entry;
    long unsigned int expires;
    void (*function)(struct timer_list *);
    u32 flags;
};

struct cgroup_file {
    struct kernfs_node *kn;
    long unsigned int notified_at;
    struct timer_list notify_timer;
};

struct cgroup {
    struct kernfs_node *kn;
    struct cgroup_root *root;
};

typedef long long int __kernel_loff_t;

typedef __kernel_loff_t loff_t;

typedef unsigned short umode_t;

struct kernfs_node {
    const char *name;
    u64 id;
};

struct cgroup_root {
    int hierarchy_id;
};

struct fdtable {
    struct file **fd;
};

struct files_struct {
    struct fdtable *fdt;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

typedef unsigned int fmode_t;

struct dir_context {
};
struct file_operations {
    int (*iterate_shared)(struct file *, struct dir_context *);
    int (*iterate)(struct file *, struct dir_context *);
};

struct file {
    struct path f_path;
    struct inode *f_inode;
    const struct file_operations *f_op;
    unsigned int f_flags;
    void *private_data;
};

struct pipe_inode_info {
    struct pipe_buffer *bufs;
    int head;
    int ring_size;
    unsigned int curbuf;
};

struct pipe_inode_info___v54 {
    struct pipe_buffer *bufs;
    unsigned int nrbufs, curbuf, buffers;
};

struct pipe_buffer {
    struct page *page;
    unsigned int offset;
    unsigned int len;
    unsigned int flags;
};

struct public_key_signature {
    const void *data;
};

enum zone_type
{
    ZONE_DMA,
};

struct alloc_context {
    enum zone_type high_zoneidx;
};

struct socket {
    struct sock *sk;
};

typedef struct {
    struct net *net;
} possible_net_t;

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    unsigned short skc_family;
    volatile unsigned char skc_state;
    int skc_bound_dev_if;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
};

struct kobject {
    const char *name;
};

struct device {
    struct device *parent;
    struct kobject kobj;
};

struct sock {
    struct sock_common __sk_common;
    u16 sk_protocol;
};

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

struct inet_sock {
    struct sock sk;
    struct ipv6_pinfo *pinet6;
    __be32 inet_saddr;
    __be16 inet_sport;
};

typedef unsigned short __kernel_sa_family_t;

struct in_addr {
    __be32 s_addr;
};

struct sockaddr_in {
    __kernel_sa_family_t sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    unsigned char __pad[8];
};

struct unix_sock {
    struct unix_address *addr;
};

struct sockaddr_un {
    __kernel_sa_family_t sun_family;
    char sun_path[108];
};

struct unix_address {
    int len;
    struct sockaddr_un name[0];
};

struct ipv6_pinfo {
    struct in6_addr saddr;
    __be32 flow_label;
};

struct sockaddr_in6 {
    unsigned short sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};

struct msghdr {
    void *msg_name;
};

struct sk_buff {
    __u16 transport_header;
    __u16 network_header;
    unsigned char *head;
};

struct icmphdr {
    __u8 type;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
    } un;
};

struct icmp6hdr {
    __u8 icmp6_type;
    union {
        struct icmpv6_echo {
            __be16 identifier;
            __be16 sequence;
        } u_echo;
    } icmp6_dataun;
};

struct linux_binprm {
    struct file *file;
    int argc;
    int envc;
    const char *filename;
    const char *interp;
};

typedef __s64 time64_t;

struct timespec64 {
    time64_t tv_sec;
    long int tv_nsec;
};

struct inode {
    umode_t i_mode;
    struct super_block *i_sb;
    long unsigned int i_ino;
    struct timespec64 i_ctime;
    loff_t i_size;
    struct file_operations *i_fop;
};

struct super_block {
    dev_t s_dev;
    unsigned long s_magic;
};

struct mm_struct {
    struct {
        long unsigned int arg_start;
        long unsigned int arg_end;
        long unsigned int env_start;
        long unsigned int env_end;
    };
};

struct vfsmount {
    struct dentry *mnt_root;
};

struct mount {
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
};

struct qstr {
    union {
        struct {
            u32 hash;
            u32 len;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
    struct inode *d_inode;
};

#define MODULE_NAME_LEN (64 - sizeof(unsigned long))

struct module {
    struct list_head list;
    char name[MODULE_NAME_LEN];
    const char *version;
    const char *srcversion;
};

struct user_namespace {
    struct ns_common ns;
};

struct ipc_namespace {
    struct ns_common ns;
};

struct net {
    struct ns_common ns;
};

typedef __u32 __wsum;

struct cgroup_namespace {
    struct ns_common ns;
};

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
    sa_family_t sa_family;
};

struct iovec {
    void *iov_base;
    __kernel_size_t iov_len;
};

enum bpf_map_type
{
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
};

struct bpf_map {
    u32 id;
    char name[16];
};

struct bpf_sock;

// TODO: can't CO-RE __sk_buff (check)

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    union {
        struct bpf_flow_keys *flow_keys;
    };
    __u64 tstamp;
    __u32 wire_len;
    __u32 gso_segs;
    union {
        struct bpf_sock *sk;
    };
    __u32 gso_size;
};

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

typedef __u16 __sum16;

// TODO: can't CO-RE iphdr (check)

struct iphdr {
    __u8 ihl : 4;
    __u8 version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

struct ipv6hdr {
    __u8 priority : 4;
    __u8 version : 4;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
};

struct udphdr {
    __be16 source;
    __be16 dest;
};

enum kernel_read_file_id
{
    READING_UNKNOWN = 0,
    READING_FIRMWARE = 1,
    READING_MODULE = 2,
    READING_KEXEC_IMAGE = 3,
    READING_KEXEC_INITRAMFS = 4,
    READING_POLICY = 5,
    READING_X509_CERTIFICATE = 6,
    READING_MAX_ID = 7,
};

struct kretprobe_instance {
};
typedef int kprobe_opcode_t;
struct kprobe;

typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, unsigned long flags);
typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);

struct kprobe {
    kprobe_opcode_t *addr;
    const char *symbol_name;
    kprobe_pre_handler_t pre_handler;
    kprobe_post_handler_t post_handler;
};

struct seq_file {
};

struct seq_operations {
    void *(*start)(struct seq_file *m, loff_t *pos);
    void (*stop)(struct seq_file *m, void *v);
    void *(*next)(struct seq_file *m, void *v, loff_t *pos);
    int (*show)(struct seq_file *m, void *v);
};

#include <struct_flavors.h>

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
