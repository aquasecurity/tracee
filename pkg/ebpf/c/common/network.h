#ifndef __TRACEE_NETWORK_H__
#define __TRACEE_NETWORK_H__

#ifndef CORE
    #include "missing_noncore_definitions.h"
#else
    // CO:RE is enabled
    #include <vmlinux.h>
    #include <missing_definitions.h>
#endif

#include <bpf/bpf_helpers.h>
#include "common/common.h"
#include "types.h"
#include "maps.h"

// clang-format off

//
// Network packet related events (TODO: spin off all net_packet related code)
//

// NOTE: proto header structs need full type in vmlinux.h (for correct skb copy)

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 0) || defined(CORE)) || defined(RHEL_RELEASE_CODE)

// network retval values
#define family_ipv4     (1 << 0)
#define family_ipv6     (1 << 1)
#define proto_http_req  (1 << 2)
#define proto_http_resp (1 << 3)

// payload size: full packets, only headers
#define FULL    65536       // 1 << 16
#define HEADERS 0           // no payload

// when guessing by src/dst ports, declare at network.h
#define UDP_PORT_DNS 53
#define TCP_PORT_DNS 53

// layer 7 parsing related constants
#define http_min_len 7 // longest http command is "DELETE "

// Type definitions and prototypes for protocol parsing

typedef union iphdrs_t {
    struct iphdr iphdr;
    struct ipv6hdr ipv6hdr;
} iphdrs;

typedef union protohdrs_t {
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmphdr icmphdr;
    struct icmp6hdr icmp6hdr;
    union {
        u8 tcp_extra[40]; // data offset might set it up to 60 bytes
    };
} protohdrs;

typedef struct nethdrs_t {
    iphdrs iphdrs;
    protohdrs protohdrs;
} nethdrs;

// cgroupctxmap

typedef enum net_packet {
    CAP_NET_PACKET = 1 << 0,
    // Layer 3
    SUB_NET_PACKET_IP = 1 << 1,
    // Layer 4
    SUB_NET_PACKET_TCP = 1 << 2,
    SUB_NET_PACKET_UDP = 1<<3,
    SUB_NET_PACKET_ICMP = 1 <<4,
    SUB_NET_PACKET_ICMPV6 = 1<<5,
    // Layer 7
    SUB_NET_PACKET_DNS = 1<< 6,
    SUB_NET_PACKET_HTTP = 1<<7,
} net_packet_t;

typedef struct net_event_contextmd {
    u8 submit;
    u32 header_size;
    u8 captured;
    u8 padding;
} __attribute__((__packed__)) net_event_contextmd_t;

typedef struct net_event_context {
    event_context_t eventctx;
    struct { // event arguments (needs packing), use anonymous struct to ...
        u8 index0;
        u32 bytes;
        // ... (payload sent by bpf_perf_event_output)
    } __attribute__((__packed__)); // ... avoid address-of-packed-member warns
    // members bellow this point are metadata (not part of event to be sent)
    net_event_contextmd_t md;
} net_event_context_t;

// network related maps

typedef struct {
    u64 ts;
    u16 ip_csum;
    struct in6_addr ip_saddr;
    struct in6_addr ip_daddr;
} indexer_t;

typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096); // 800 KB    // simultaneous cgroup/skb ingress/eggress progs
    __type(key, indexer_t);                 // layer 3 header fields used as indexer
    __type(value, net_event_context_t);     // event context built so cgroup/skb can use
} cgrpctxmap_t;

cgrpctxmap_t cgrpctxmap_in SEC(".maps");    // saved info SKB caller <=> SKB ingress
cgrpctxmap_t cgrpctxmap_eg SEC(".maps");    // saved info SKB caller <=> SKB egress

// inodemap

typedef struct net_task_context {
    struct task_struct *task;
    task_context_t taskctx;
    u64 matched_policies;
    int syscall;
} net_task_context_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535); // 9 MB     // simultaneous sockets being traced
    __type(key, u64);                       // socket inode number ...
    __type(value, struct net_task_context); // ... linked to a task context
} inodemap SEC(".maps");                    // relate sockets and tasks

// entrymap

typedef struct entry {
    long unsigned int args[6];
} entry_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);              // simultaneous tasks being traced for entry/exit
    __type(key, u32);                       // host thread group id (tgid or tid) ...
    __type(value, struct entry);            // ... linked to entry ctx->args
} entrymap SEC(".maps");                    // can't use args_map (indexed by existing events only)

// network capture events

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} net_cap_events SEC(".maps");

// scratch area

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);                 // simultaneous softirqs running per CPU (?)
    __type(key, u32);                       // per cpu index ... (always zero)
    __type(value, scratch_t);               // ... linked to a scratch area
} net_heap_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);                 // simultaneous softirqs running per CPU (?)
    __type(key, u32);                       // per cpu index ... (always zero)
    __type(value, event_data_t);            // ... linked to a scratch area
} net_heap_event SEC(".maps");

    // clang-format on

#endif

//
// Regular events related to network
//

static __always_inline u32 get_inet_rcv_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_rcv_saddr);
}

static __always_inline u32 get_inet_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_saddr);
}

static __always_inline u32 get_inet_daddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_daddr);
}

static __always_inline u16 get_inet_sport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_sport);
}

static __always_inline u16 get_inet_num(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_num);
}

static __always_inline u16 get_inet_dport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_dport);
}

static __always_inline struct sock *get_socket_sock(struct socket *socket)
{
    return READ_KERN(socket->sk);
}

static __always_inline u16 get_sock_family(struct sock *sock)
{
    return READ_KERN(sock->sk_family);
}

static __always_inline u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    // kernel 4.18-5.5: sk_protocol bit-field: use sk_gso_max_segs field and go
    // back 24 bits to reach sk_protocol field index.
    bpf_probe_read(&protocol, 1, (void *) (&sock->sk_gso_max_segs) - 3);
    #else
    // kernel 5.6
    protocol = READ_KERN(sock->sk_protocol);
    #endif
#else // CORE
    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset)) {
        check = (struct sock___old *) sock;
        bpf_core_read(&protocol, 1, (void *) (&check->sk_gso_max_segs) - 3);
    } else {
        protocol = READ_KERN(sock->sk_protocol);
    }
#endif

    return protocol;
}

static __always_inline u16 get_sockaddr_family(struct sockaddr *address)
{
    return READ_KERN(address->sa_family);
}

static __always_inline struct in6_addr get_sock_v6_rcv_saddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_rcv_saddr);
}

static __always_inline struct in6_addr get_ipv6_pinfo_saddr(struct ipv6_pinfo *np)
{
    return READ_KERN(np->saddr);
}

static __always_inline struct in6_addr get_sock_v6_daddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_daddr);
}

static __always_inline volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_probe_read(
        (void *) &sk_state_own_impl, sizeof(sk_state_own_impl), (const void *) &sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo *get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct sockaddr_un get_unix_sock_addr(struct unix_sock *sock)
{
    struct unix_address *addr = READ_KERN(sock->addr);
    int len = READ_KERN(addr->len);
    struct sockaddr_un sockaddr = {};
    if (len <= sizeof(struct sockaddr_un)) {
        bpf_probe_read(&sockaddr, len, addr->name);
    }
    return sockaddr;
}

static __always_inline int
get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!peer) {
        net_details->local_address = get_inet_rcv_saddr(inet);
        net_details->local_port = bpf_ntohs(get_inet_num(inet));
        net_details->remote_address = get_inet_daddr(inet);
        net_details->remote_port = get_inet_dport(inet);
    } else {
        net_details->remote_address = get_inet_rcv_saddr(inet);
        net_details->remote_port = bpf_ntohs(get_inet_num(inet));
        net_details->local_address = get_inet_daddr(inet);
        net_details->local_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk,
                                                            struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

static __always_inline int
get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details, int peer)
{
    // inspired by 'inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)'
    // reference: https://elixir.bootlin.com/linux/latest/source/net/ipv6/af_inet6.c#L509

    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);

    struct in6_addr addr = {};
    addr = get_sock_v6_rcv_saddr(sk);
    if (ipv6_addr_any(&addr)) {
        addr = get_ipv6_pinfo_saddr(np);
    }

    // the flowinfo field can be specified by the user to indicate a network flow. how it is used by
    // the kernel, or whether it is enforced to be unique is not so obvious.  getting this value is
    // only supported by the kernel for outgoing packets using the 'struct ipv6_pinfo'.  in any
    // case, leaving it with value of 0 won't affect our representation of network flows.
    net_details->flowinfo = 0;

    // the scope_id field can be specified by the user to indicate the network interface from which
    // to send a packet. this only applies for link-local addresses, and is used only by the local
    // kernel.  getting this value is done by using the 'ipv6_iface_scope_id(const struct in6_addr
    // *addr, int iface)' function.  in any case, leaving it with value of 0 won't affect our
    // representation of network flows.
    net_details->scope_id = 0;

    if (peer) {
        net_details->local_address = get_sock_v6_daddr(sk);
        net_details->local_port = get_inet_dport(inet);
        net_details->remote_address = addr;
        net_details->remote_port = get_inet_sport(inet);
    } else {
        net_details->local_address = addr;
        net_details->local_port = get_inet_sport(inet);
        net_details->remote_address = get_sock_v6_daddr(sk);
        net_details->remote_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline int get_local_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                                      net_conn_v4_t *net_details,
                                                                      u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->local_port;
    addr->sin_addr.s_addr = net_details->local_address;

    return 0;
}

static __always_inline int get_remote_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                                       net_conn_v4_t *net_details,
                                                                       u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;

    return 0;
}

static __always_inline int get_local_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                                       net_conn_v6_t *net_details,
                                                                       u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->local_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->local_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                                        net_conn_v6_t *net_details,
                                                                        u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v4(struct sock *sk,
                                                                    net_id_t *connect_id,
                                                                    net_conn_v4_t *net_details,
                                                                    u16 family)
{
    connect_id->address.s6_addr32[3] = net_details->local_address;
    connect_id->address.s6_addr16[5] = 0xffff;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v6(struct sock *sk,
                                                                    net_id_t *connect_id,
                                                                    net_conn_v6_t *net_details,
                                                                    u16 family)
{
    connect_id->address = net_details->local_address;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

#endif
